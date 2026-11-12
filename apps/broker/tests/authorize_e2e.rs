//! End-to-end authorize + record + chain tests using a mock issuer.

/// Process-unique suffix for temp directories. `SystemTime` alone is not enough on
/// platforms with coarse clock resolution (two threads can read the same value).
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use tower::ServiceExt;

use tessera_broker::authorize::{
    AuthorizeRequest, AuthorizeService, Decision, PrincipalInput, RecordRequest,
};
use tessera_broker::chain::MemoryChainStore;
use tessera_broker::issuers::mock::MockIssuer;
use tessera_broker::issuers::IssuerRegistry;
use tessera_broker::policy::{Constraint, InMemoryPolicyStore, Policy, PolicyStore, ResourceGrant};
use tessera_broker::receipt::ReceiptSigner;

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

fn rh(byte: u8) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(32))
}

async fn service(demo: bool) -> Arc<AuthorizeService> {
    service_opts(demo, None, Vec::new(), 3600).await
}

/// Build a service with an optional per-agent rate limit (requests/minute).
async fn service_with(demo: bool, agent_rate_limit_per_min: Option<u32>) -> Arc<AuthorizeService> {
    service_opts(demo, agent_rate_limit_per_min, Vec::new(), 3600).await
}

/// Full-control builder for rate-limit and TTL tests.
async fn service_opts(
    demo: bool,
    agent_rate_limit_per_min: Option<u32>,
    tool_rate_limits: Vec<(String, u32)>,
    max_ttl_seconds: u32,
) -> Arc<AuthorizeService> {
    let signer =
        Arc::new(ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 84532, ZERO_ADDR).unwrap());

    let policies = InMemoryPolicyStore::new();
    policies
        .upsert(
            "acme",
            Policy {
                id: "acme-refunds".into(),
                version: 7,
                name: "Refunds under $50".into(),
                grants: vec![ResourceGrant {
                    resource: "stripe:refunds.create".into(),
                    constraints: vec![Constraint::MaxNumber {
                        field: "amount".into(),
                        value: 5000.0,
                    }],
                    condition: None,
                }],
                fail_open: false,
                limits: Default::default(),
            },
        )
        .await
        .unwrap();

    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(MockIssuer::new("stripe")));

    Arc::new(AuthorizeService {
        policies: Arc::new(policies),
        issuers: Arc::new(issuers),
        authority_hmac_secret: None,
        authority_require_token: false,
        signer,
        chain: Arc::new(MemoryChainStore::new()),
        telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        anchor: None,
        anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: Arc::new(tessera_broker::anchoring::MemoryAnchorTargetStore::new()),
        secrets: None,
        rpc_policy: Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min,
        retention_days: 90,
        anchor_confirmations: 12,
        anchor_reorg_grace_secs: 300,
        revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http: reqwest::Client::new(),
        alert_acks: std::sync::Arc::new(tessera_broker::alert_acks::MemoryAlertAcks::new()),
        key_events: std::sync::Arc::new(tessera_broker::key_events::MemoryKeyEvents::new()),
        chain_checkpoints: std::sync::Arc::new(
            tessera_broker::chain_checkpoints::MemoryChainCheckpoints::new(),
        ),
        quota: std::sync::Arc::new(tessera_broker::quota::QuotaManager::disabled()),
        remediation_policies: std::sync::Arc::new(
            tessera_broker::remediation::MemoryRemediationPolicies::new(),
        ),
        tool_pins: std::sync::Arc::new(tessera_broker::tool_pins::MemoryToolPins::new()),
        alert_router: std::sync::Arc::new(tessera_broker::alerts::AlertRouter::new(
            std::sync::Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
            None,
            None,
        )),
        key_expiry_alert_days: 0,
        key_rotation_max_age_hours: None,
        default_ttl_seconds: 30,
        max_ttl_seconds,
        signing_key_history: Vec::new(),
        anchor_gap_threshold: 100,
        ledger_retention_days: 0,
        archive_dir: None,
        archive_interval_secs: 3600,
        archive_replica_dir: None,
        archive_retention_days: 0,
        alert_webhook_url: None,
        alert_webhook_token: None,
        alert_repeat_secs: 3600,
        alert_retry_secs: 60,
        gap_alerts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        tool_rate_limits,
        demo_policy: if demo {
            Some(tessera_broker::policy::demo_policy())
        } else {
            None
        },
    })
}

fn request(amount: i64) -> AuthorizeRequest {
    request_args(serde_json::json!({ "charge": "ch_123", "amount": amount }))
}

fn request_args(args: serde_json::Value) -> AuthorizeRequest {
    AuthorizeRequest {
        agent_id: "billing-agent".into(),
        user_id: "user_42".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund a duplicate charge".into(),
        args,
        tool_schema_hash: None,
        ..Default::default()
    }
}

/// Wrap a service in an `AppState` with demo auth enabled.
fn app_of(svc: Arc<AuthorizeService>) -> axum::Router {
    tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: Arc::new(tessera_broker::MemoryApiKeyStore::new()),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }))
}

#[tokio::test]
async fn allows_within_policy_and_signs_receipt() {
    let svc = service(false).await;
    let resp = svc.authorize("acme", request(4200)).await.unwrap();

    assert_eq!(resp.decision, Decision::Allow);
    assert!(resp.credential.is_some());
    assert_eq!(resp.receipt.authorization.policy, "acme-refunds");
    assert_eq!(resp.receipt.authorization.policy_version, 7);
    assert!(resp.receipt.signature.is_some());
    assert!(!resp.receipt_id.is_empty());
    assert_eq!(resp.receipt.v, 2);
    assert_eq!(
        resp.receipt.action_id.as_deref(),
        Some(resp.action_id.as_str())
    );
    assert!(resp.receipt.principal.is_some());
    assert!(resp.receipt.agent_meta.is_some());
    assert!(resp.receipt.policy.is_some());
    assert!(resp.receipt.credential.is_some());
    assert!(resp.receipt.attestation.is_some());
    tessera_broker::receipt::validate_v2(&resp.receipt).unwrap();
    assert!(svc
        .signer
        .verify(&resp.receipt, &svc.signer.address_hex())
        .unwrap());

    let cred = resp.credential.unwrap();
    assert_eq!(cred.args_hash, resp.receipt.call.args_hash);
    assert_eq!(resp.receipt.prev, None);
}

#[tokio::test]
async fn verifies_hmac_authority_tokens() {
    const SECRET: &str = "tessera-test-authority-secret-32-bytes-minimum";
    let mut svc = service(true).await;
    {
        let inner = Arc::get_mut(&mut svc).expect("unique service");
        inner.authority_hmac_secret = Some(SECRET.to_string());
        inner.authority_require_token = true;
    }
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": "user_42",
        "exp": now + 60,
        "iat": now,
        "jti": "consent_1",
        "principal_type": "user"
    });
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();

    let mut req = request(100);
    req.authority_token = Some(token.clone());
    let resp = svc.authorize("acme", req).await.unwrap();
    assert_eq!(resp.decision, Decision::Allow);
    let principal = resp.receipt.principal.as_ref().unwrap();
    assert_eq!(principal.principal_id, "user_42");
    assert_eq!(principal.authority_ref, "consent_1");
    assert_eq!(principal.verification_method, "hmac-jwt");

    // A missing token is rejected when the deployment requires one.
    let err = svc.authorize("acme", request(100)).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));

    // A token for a different principal cannot be paired with a caller-asserted principal.
    let mut req = request(100);
    req.authority_token = Some(token.clone());
    req.principal = Some(PrincipalInput {
        principal_id: "someone_else".into(),
        principal_type: Some("user".into()),
        authority_ref: "consent_1".into(),
        authority_hash: tessera_broker::canonical::keccak256_str("placeholder"),
        verified_at: None,
        verification_method: Some("caller".into()),
    });
    let err = svc.authorize("acme", req).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));

    // A tampered token is rejected.
    let mut req = request(100);
    req.authority_token = Some(format!("{token}x"));
    let err = svc.authorize("acme", req).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));

    // A token cannot be used when the deployment has no verifier configured.
    let unconfigured = service(true).await;
    let mut req = request(100);
    req.authority_token = Some(token.clone());
    let err = unconfigured.authorize("acme", req).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));

    // The verified subject is authoritative for policy and the receipt user field.
    let alice_claims = serde_json::json!({
        "sub": "alice",
        "exp": now + 60,
        "iat": now
    });
    let alice_token = encode(
        &Header::new(Algorithm::HS256),
        &alice_claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    let mut req = request(100);
    req.user_id = "caller_supplied".into();
    req.authority_token = Some(alice_token);
    let resp = svc.authorize("acme", req).await.unwrap();
    assert_eq!(resp.receipt.user, "alice");
    assert_eq!(
        resp.receipt.principal.as_ref().unwrap().principal_id,
        "alice"
    );

    // Excessively long-lived tokens are rejected.
    let long_claims = serde_json::json!({
        "sub": "user_42",
        "exp": now + 90_000,
        "iat": now
    });
    let long_token = encode(
        &Header::new(Algorithm::HS256),
        &long_claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    let mut req = request(100);
    req.authority_token = Some(long_token);
    let err = svc.authorize("acme", req).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));
}

#[tokio::test]
async fn rejects_invalid_v2_authority_hash_before_policy() {
    let svc = service(true).await;
    let mut req = request(100);
    req.principal = Some(PrincipalInput {
        principal_id: "user_42".into(),
        principal_type: Some("user".into()),
        authority_ref: "oauth_grant_1".into(),
        authority_hash: "0x00".into(),
        verified_at: None,
        verification_method: Some("oidc".into()),
    });
    let err = svc.authorize("acme", req).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));
}

#[tokio::test]
async fn rejects_outcome_for_a_denied_authorization() {
    let svc = service(true).await;
    let denied = svc.authorize("acme", request(900_000)).await.unwrap();
    assert_eq!(denied.decision, Decision::Deny);
    let err = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: denied.receipt_id,
                result_hash: rh(0x33),
                status: Some("success".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));
}

#[tokio::test]
async fn rejects_invalid_v2_result_hash() {
    let svc = service(true).await;
    let auth = svc.authorize("acme", request(100)).await.unwrap();
    let err = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: auth.receipt_id,
                result_hash: "0xnot-a-hash".into(),
                status: Some("success".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));
}

#[tokio::test]
async fn denies_over_limit_and_still_signs() {
    let svc = service(false).await;
    let resp = svc.authorize("acme", request(900_000)).await.unwrap();

    assert_eq!(resp.decision, Decision::Deny);
    assert!(resp.credential.is_none());
    assert_eq!(resp.receipt.grant.status, "denied");
    tessera_broker::receipt::validate_v2(&resp.receipt).unwrap();
    assert!(svc
        .signer
        .verify(&resp.receipt, &svc.signer.address_hex())
        .unwrap());
}

#[tokio::test]
async fn denies_unknown_tenant_without_demo_policy() {
    let svc = service(false).await;
    let resp = svc.authorize("unknown", request(100)).await.unwrap();
    assert_eq!(resp.decision, Decision::Deny);
}

#[tokio::test]
async fn demo_policy_allows_unknown_tenant() {
    let svc = service(true).await;
    let resp = svc.authorize("unknown", request(100)).await.unwrap();
    assert_eq!(resp.decision, Decision::Allow);
}

#[tokio::test]
async fn chain_links_authorize_and_record() {
    let svc = service(true).await;

    let auth = svc.authorize("acme", request(100)).await.unwrap();
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 1);

    let rec = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: auth.receipt_id.clone(),
                result_hash: rh(0x11),
                status: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(rec.chain_length, 2);
    assert_eq!(
        rec.receipt.call.result_hash.as_deref(),
        Some(rh(0x11).as_str())
    );
    assert_eq!(rec.receipt.grant.status, "used");
    assert_eq!(rec.receipt.action_id, auth.receipt.action_id);
    let outcome = rec.receipt.outcome.as_ref().unwrap();
    assert_eq!(outcome.status, "unknown");
    assert_eq!(outcome.result_hash.as_deref(), Some(rh(0x11).as_str()));
    // the outcome receipt links to the authorization receipt
    assert_eq!(rec.receipt.prev.as_deref(), Some(auth.receipt_id.as_str()));
    // and the whole chain verifies
    assert!(svc.verify_chain("acme", "billing-agent").await.unwrap());
}

#[tokio::test]
async fn record_rejects_unknown_receipt() {
    let svc = service(true).await;
    let err = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "nobody".into(),
                receipt_id: "0xdeadbeef".into(),
                result_hash: rh(0x00),
                status: None,
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(err, Err(tessera_broker::BrokerError::NotFound(_))));
}

#[tokio::test]
async fn http_authorize_record_and_chain() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    let body = serde_json::json!({
        "agentId": "a1", "userId": "u1",
        "tool": "stripe.refunds.create", "intent": "refund",
        "args": { "amount": 100 }
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let authorized: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(authorized["decision"], "allow");
    let receipt_id = authorized["receiptId"].as_str().unwrap().to_string();

    // record the outcome
    let rec_body = serde_json::json!({
        "agentId": "a1", "receiptId": receipt_id, "resultHash": rh(0x11)
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/record")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(rec_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // inspect + verify the chain
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/chain/a1")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let chain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(chain["length"], 2);
    assert_eq!(chain["verified"], true);
}

#[tokio::test]
async fn http_record_unknown_receipt_returns_404() {
    let svc = service(true).await;
    let app = app_of(svc);
    let rec_body = serde_json::json!({
        "agentId": "a1", "receiptId": "0xdead", "resultHash": rh(0x00)
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/record")
                .header("content-type", "application/json")
                .body(Body::from(rec_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn anchor_batch_covers_chain() {
    let svc = service(true).await;
    svc.authorize("acme", request(1)).await.unwrap();
    svc.authorize("acme", request(2)).await.unwrap();

    let batch = svc.anchor_batch("acme", "billing-agent").await.unwrap();
    assert_eq!(batch.count, 2);
    assert_eq!(batch.leaves.len(), 2);
    assert!(batch.root.starts_with("0x"));
    assert!(batch.calldata.starts_with("0x15954b2c"));
}

#[tokio::test]
async fn record_is_idempotent() {
    let svc = service(true).await;
    let auth = svc.authorize("acme", request(1)).await.unwrap();

    let make = || RecordRequest {
        agent_id: "billing-agent".into(),
        receipt_id: auth.receipt_id.clone(),
        result_hash: rh(0x11),
        status: None,
        ..Default::default()
    };

    let first = svc.record("acme", make()).await.unwrap();
    assert!(!first.duplicate);
    assert_eq!(first.chain_length, 2);

    let second = svc.record("acme", make()).await.unwrap();
    assert!(second.duplicate);
    assert_eq!(second.chain_length, 2, "no duplicate append");
    assert_eq!(second.receipt_id, first.receipt_id);
    assert!(svc.verify_chain("acme", "billing-agent").await.unwrap());
}

#[tokio::test]
async fn record_rejects_a_conflicting_outcome() {
    let svc = service(true).await;
    let auth = svc.authorize("acme", request(1)).await.unwrap();
    let make = |hash: String| RecordRequest {
        agent_id: "billing-agent".into(),
        receipt_id: auth.receipt_id.clone(),
        result_hash: hash,
        status: Some("success".into()),
        ..Default::default()
    };
    svc.record("acme", make(rh(0x11))).await.unwrap();
    let err = svc.record("acme", make(rh(0x22))).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));
}

#[tokio::test]
async fn concurrent_authorize_keeps_chain_consistent() {
    let svc = service(true).await;
    let mut handles = Vec::new();
    for i in 0..25i64 {
        let svc = svc.clone();
        handles.push(tokio::spawn(async move {
            svc.authorize("acme", request(100 + i)).await.unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 25);
    assert!(svc.verify_chain("acme", "billing-agent").await.unwrap());
}

#[tokio::test]
async fn proposed_policy_generalizes_and_blocks_drift() {
    // Use a tenant with no pre-existing policy so the proposed policy is the only one.
    let svc = service(true).await;
    let tenant = "newco";

    for amount in [100, 250, 900, 400] {
        svc.authorize(
            tenant,
            request_args(serde_json::json!({ "amount": amount, "currency": "usd" })),
        )
        .await
        .unwrap();
    }

    let proposal = svc.propose_policy(tenant).await.unwrap();
    svc.policies
        .upsert(tenant, proposal.policy.clone())
        .await
        .unwrap();

    // a new in-distribution call is allowed
    assert_eq!(
        svc.authorize(
            tenant,
            request_args(serde_json::json!({ "amount": 500, "currency": "usd" }))
        )
        .await
        .unwrap()
        .decision,
        Decision::Allow
    );

    // amount beyond the observed max is denied
    assert_eq!(
        svc.authorize(
            tenant,
            request_args(serde_json::json!({ "amount": 100_000, "currency": "usd" }))
        )
        .await
        .unwrap()
        .decision,
        Decision::Deny
    );

    // unseen currency is denied (allowlist)
    assert_eq!(
        svc.authorize(
            tenant,
            request_args(serde_json::json!({ "amount": 500, "currency": "eur" }))
        )
        .await
        .unwrap()
        .decision,
        Decision::Deny
    );
}

#[tokio::test]
async fn tenant_isolation_on_chain_record_and_anchor() {
    let svc = service(true).await;
    let app = app_of(svc);

    // Tenant A authorizes.
    let body = serde_json::json!({
        "agentId": "iso-agent", "userId": "u", "tool": "stripe.refunds.create",
        "intent": "refund", "args": { "amount": 1 }
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "A")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let authorized: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let receipt_id = authorized["receiptId"].as_str().unwrap().to_string();

    let get_chain = |tenant: &str| {
        app.clone().oneshot(
            Request::builder()
                .uri("/v1/chain/iso-agent")
                .header("x-tessera-tenant", tenant)
                .body(Body::empty())
                .unwrap(),
        )
    };
    let anchor = |tenant: &str| {
        app.clone().oneshot(
            Request::builder()
                .uri("/v1/chain/iso-agent/anchor")
                .header("x-tessera-tenant", tenant)
                .body(Body::empty())
                .unwrap(),
        )
    };
    let record = |tenant: &str, receipt: String| {
        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/record")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", tenant)
                .body(Body::from(
                    serde_json::json!({"agentId":"iso-agent","receiptId":receipt,"resultHash":rh(0x00)}).to_string(),
                ))
                .unwrap(),
        )
    };

    // Owner can read / record / anchor.
    assert_eq!(get_chain("A").await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        record("A", receipt_id.clone()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(anchor("A").await.unwrap().status(), StatusCode::OK);

    // Another tenant has its own (empty) chain for the same agent id: no data leaks.
    let resp = get_chain("B").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let chain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        chain["length"], 0,
        "tenant B must not see tenant A's receipts"
    );

    // Recording against another tenant's receipt is not found.
    assert_eq!(
        record("B", receipt_id.clone()).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    // B's anchor batch is empty (its own namespace), and there is nothing to submit.
    let resp = anchor("B").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let batch: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(batch["count"], 0);

    let submit = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/chain/iso-agent/anchor/submit")
            .header("x-tessera-tenant", "B")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(submit.await.unwrap().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn same_agent_id_is_isolated_per_tenant() {
    let svc = service(true).await;

    // Both tenants use the agent id "shared"; each gets an independent chain.
    let a = svc.authorize("tenant-a", request(1)).await.unwrap();
    let b = svc.authorize("tenant-b", request(2)).await.unwrap();
    let a2 = svc.authorize("tenant-a", request(3)).await.unwrap();

    assert_eq!(svc.chain.len("tenant-a", "billing-agent").await.unwrap(), 2);
    assert_eq!(svc.chain.len("tenant-b", "billing-agent").await.unwrap(), 1);
    assert!(svc.verify_chain("tenant-a", "billing-agent").await.unwrap());
    assert!(svc.verify_chain("tenant-b", "billing-agent").await.unwrap());

    // Chains are distinct: neither tenant's receipts appear in the other's chain.
    let a_chain = svc.chain.chain("tenant-a", "billing-agent").await.unwrap();
    let b_chain = svc.chain.chain("tenant-b", "billing-agent").await.unwrap();
    assert!(a_chain.iter().all(|e| e.receipt.tenant == "tenant-a"));
    assert!(b_chain.iter().all(|e| e.receipt.tenant == "tenant-b"));
    assert!(!a_chain.iter().any(|e| e.payload_hash == b.receipt_id));
    assert!(a_chain.iter().any(|e| e.payload_hash == a.receipt_id));
    assert!(a_chain.iter().any(|e| e.payload_hash == a2.receipt_id));
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let svc = service(true).await;
    let app = app_of(svc);

    let big = "x".repeat(200 * 1024);
    let body = serde_json::json!({
        "agentId": "a", "userId": "u", "tool": "stripe.refunds.create",
        "intent": "refund", "args": { "pad": big }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn revoked_agent_is_denied() {
    let svc = service(true).await;
    assert_eq!(
        svc.authorize("acme", request(100)).await.unwrap().decision,
        Decision::Allow
    );
    svc.revoke("acme", "billing-agent", "agent", Some("compromised".into()))
        .await
        .unwrap();
    let denied = svc.authorize("acme", request(100)).await.unwrap();
    assert_eq!(denied.decision, Decision::Deny);
    assert!(
        denied.reason.contains("revoked"),
        "reason: {}",
        denied.reason
    );
}

#[tokio::test]
async fn http_revoke_endpoint() {
    let svc = service(true).await;
    let app = app_of(svc);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/revoke")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"target": "grant_stripe_abc", "kind": "grant", "reason": "leak"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["event"]["kind"], "grant");
    assert_eq!(value["provider"], "stripe");
    assert_eq!(value["capability"], "broker-grant-invalidation");
}

#[tokio::test]
async fn http_step_up_appends_a_signed_authority_transition() {
    let svc = service(true).await;
    let app = app_of(svc);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/transitions")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({
                        "type": "authority.stepped_up",
                        "target": "billing-agent",
                        "reason": "MFA challenge"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["kind"], "authority.stepped_up");
    assert_eq!(value["details"]["transitionType"], "authority.stepped_up");
}

#[tokio::test]
async fn revocation_appends_a_signed_authority_transition() {
    let svc = service(true).await;
    svc.revoke("acme", "grant_stripe_abc", "grant", Some("leak".into()))
        .await
        .unwrap();
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    let events = log["items"].as_array().unwrap();
    let transition = events
        .iter()
        .find(|event| event["kind"] == "authority.revoked")
        .expect("authority transition event");
    assert_eq!(transition["details"]["transitionType"], "authority.revoked");
    assert_eq!(transition["details"]["target"], "grant_stripe_abc");
    assert_eq!(log["verified"], true);
    assert_eq!(log["signaturesValid"], true);
}

#[tokio::test]
async fn responses_disable_sniffing_and_caching() {
    let app = app_of(service(true).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn http_verify_receipt_and_chain() {
    let svc = service(true).await;
    let signer_addr = svc.signer.address_hex();
    let auth = svc.authorize("acme", request(100)).await.unwrap();
    let mut receipt = serde_json::to_value(&auth.receipt).unwrap();
    receipt
        .as_object_mut()
        .unwrap()
        .insert("expectedSigner".into(), serde_json::json!(signer_addr));
    let chain = svc.chain.chain("acme", "billing-agent").await.unwrap();
    let entries = serde_json::to_value(&chain).unwrap();

    let app = app_of(svc);

    // Receipt verification (public, no API key).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify/receipt")
                .header("content-type", "application/json")
                .body(Body::from(receipt.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["matchesExpected"], true);

    // Chain verification.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify/chain")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "entries": entries }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["length"], 1);

    // Tampered chain fails.
    let mut tampered = entries.clone();
    tampered[0]["receipt"]["call"]["argsHash"] = serde_json::json!("0xtampered");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify/chain")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "entries": tampered }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["valid"], false);
}

#[tokio::test]
async fn http_verify_domain_and_merkle() {
    let svc = service(true).await;
    let app = app_of(svc);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/verify/domain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify/merkle")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "leaf": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "proof": []
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["valid"], true); // zero leaf, empty proof, zero root
}

#[tokio::test]
async fn propose_policy_from_telemetry() {
    let svc = service(true).await;
    for (amount, currency) in [(100, "usd"), (700, "usd"), (250, "eur")] {
        svc.authorize(
            "acme",
            request_args(serde_json::json!({ "amount": amount, "currency": currency })),
        )
        .await
        .unwrap();
    }

    let proposal = svc.propose_policy("acme").await.unwrap();
    assert_eq!(proposal.policy.grants.len(), 1);
    let constraints = &proposal.policy.grants[0].constraints;
    assert!(constraints
        .iter()
        .any(|c| matches!(c, Constraint::MaxNumber { field, value } if field == "amount" && *value == 700.0)));
    assert!(constraints
        .iter()
        .any(|c| matches!(c, Constraint::MinNumber { field, value } if field == "amount" && *value == 100.0)));
    assert!(constraints
        .iter()
        .any(|c| matches!(c, Constraint::Allowlist { field, .. } if field == "currency")));
    assert!(constraints
        .iter()
        .any(|c| matches!(c, Constraint::Required { field } if field == "amount")));
}

#[tokio::test]
async fn http_propose_policy_endpoint() {
    let svc = service(true).await;
    svc.authorize("acme", request(100)).await.unwrap();
    let app = app_of(svc);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/policies/propose")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["policy"]["grants"].as_array().unwrap().len(), 1);
    assert!(!value["evidence"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn http_anchor_endpoint() {
    let svc = service(true).await;
    svc.authorize("acme", request(1)).await.unwrap();
    let app = app_of(svc);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/chain/billing-agent/anchor")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["count"], 1);
    assert!(value["calldata"]
        .as_str()
        .unwrap()
        .starts_with("0x15954b2c"));
}

#[tokio::test]
async fn http_policy_crud() {
    let svc = service(false).await;
    let app = app_of(svc);

    let policy_body = serde_json::json!({
        "version": 1,
        "name": "Test policy",
        "grants": [{
            "resource": "stripe:refunds.create",
            "constraints": [],
            "condition": "amount <= 100"
        }],
        "fail_open": false
    });

    // PUT — the id comes from the path.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/policies/new-pol")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(policy_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET collection now returns the seeded policy plus the new one.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/policies")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 2);

    // GET one.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/policies/new-pol")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // DELETE.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/policies/new-pol")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET one -> 404.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/policies/new-pol")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn anchor_target_key_is_encrypted_and_redacted() {
    use tessera_broker::anchoring::AnchorTarget;
    use tessera_broker::secrets::{is_encrypted, Envelope};

    const ENC_KEY: &str = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let signer =
        Arc::new(ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 84532, ZERO_ADDR).unwrap());
    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(MockIssuer::new("stripe")));
    let svc = Arc::new(tessera_broker::authorize::AuthorizeService {
        policies: Arc::new(InMemoryPolicyStore::new()),
        issuers: Arc::new(issuers),
        authority_hmac_secret: None,
        authority_require_token: false,
        signer,
        chain: Arc::new(MemoryChainStore::new()),
        telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http: reqwest::Client::new(),
        alert_acks: std::sync::Arc::new(tessera_broker::alert_acks::MemoryAlertAcks::new()),
        key_events: std::sync::Arc::new(tessera_broker::key_events::MemoryKeyEvents::new()),
        chain_checkpoints: std::sync::Arc::new(
            tessera_broker::chain_checkpoints::MemoryChainCheckpoints::new(),
        ),
        quota: std::sync::Arc::new(tessera_broker::quota::QuotaManager::disabled()),
        remediation_policies: std::sync::Arc::new(
            tessera_broker::remediation::MemoryRemediationPolicies::new(),
        ),
        tool_pins: std::sync::Arc::new(tessera_broker::tool_pins::MemoryToolPins::new()),
        alert_router: std::sync::Arc::new(tessera_broker::alerts::AlertRouter::new(
            std::sync::Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
            None,
            None,
        )),
        key_expiry_alert_days: 0,
        key_rotation_max_age_hours: None,
        anchor: None,
        anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: Arc::new(tessera_broker::anchoring::MemoryAnchorTargetStore::new()),
        secrets: Some(Arc::new(Envelope::from_hex(ENC_KEY).unwrap())),
        rpc_policy: Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min: None,
        retention_days: 90,
        anchor_confirmations: 12,
        anchor_reorg_grace_secs: 300,
        default_ttl_seconds: 30,
        max_ttl_seconds: 3600,
        signing_key_history: Vec::new(),
        anchor_gap_threshold: 100,
        ledger_retention_days: 0,
        archive_dir: None,
        archive_interval_secs: 3600,
        archive_replica_dir: None,
        archive_retention_days: 0,
        alert_webhook_url: None,
        alert_webhook_token: None,
        alert_repeat_secs: 3600,
        alert_retry_secs: 60,
        gap_alerts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        tool_rate_limits: Vec::new(),
        demo_policy: Some(tessera_broker::policy::demo_policy()),
    });

    let target = AnchorTarget {
        chain_id: 84532,
        rpc_url: "http://127.0.0.1:8545".into(),
        contract: "0x1111111111111111111111111111111111111111".into(),
        private_key: Some(TEST_KEY.into()),
        signer_history: Vec::new(),
    };
    let stored = svc.set_anchor_target("acme", target.clone()).await.unwrap();

    // Ciphertext at rest, never the plaintext key.
    let ciphertext = stored.private_key.clone().unwrap();
    assert!(is_encrypted(&ciphertext));
    assert!(!ciphertext.contains(TEST_KEY));
    let in_store = svc.anchor_targets.get("acme").await.unwrap().unwrap();
    assert!(is_encrypted(in_store.private_key.as_deref().unwrap()));

    // The stored key is usable: it resolves to the signer's address.
    assert_eq!(
        svc.anchor_signer_address("acme").await.unwrap(),
        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    );

    // HTTP returns the target without the key.
    let app = app_of(svc);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/anchor-config")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["target"]["hasPrivateKey"], true);
    assert!(body["target"].get("privateKey").is_none());
    assert!(!body.to_string().contains(TEST_KEY));

    // Without an envelope key, storing a tenant key is refused.
    let plain = service(true).await;
    assert!(plain.set_anchor_target("acme", target).await.is_err());
}

#[tokio::test]
async fn tenant_rpc_urls_are_ssrf_checked() {
    use tessera_broker::anchoring::AnchorTarget;
    use tessera_broker::netguard::RpcPolicy;

    async fn service_with_policy(
        policy: RpcPolicy,
    ) -> Arc<tessera_broker::authorize::AuthorizeService> {
        let signer =
            Arc::new(ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 84532, ZERO_ADDR).unwrap());
        let mut issuers = IssuerRegistry::new();
        issuers.register(Arc::new(MockIssuer::new("stripe")));
        Arc::new(tessera_broker::authorize::AuthorizeService {
            policies: Arc::new(InMemoryPolicyStore::new()),
            issuers: Arc::new(issuers),
            authority_hmac_secret: None,
            authority_require_token: false,
            signer,
            chain: Arc::new(MemoryChainStore::new()),
            telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
            revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
            http: reqwest::Client::new(),
            alert_acks: std::sync::Arc::new(tessera_broker::alert_acks::MemoryAlertAcks::new()),
            key_events: std::sync::Arc::new(tessera_broker::key_events::MemoryKeyEvents::new()),
            chain_checkpoints: std::sync::Arc::new(
                tessera_broker::chain_checkpoints::MemoryChainCheckpoints::new(),
            ),
            quota: std::sync::Arc::new(tessera_broker::quota::QuotaManager::disabled()),
            remediation_policies: std::sync::Arc::new(
                tessera_broker::remediation::MemoryRemediationPolicies::new(),
            ),
            tool_pins: std::sync::Arc::new(tessera_broker::tool_pins::MemoryToolPins::new()),
            alert_router: std::sync::Arc::new(tessera_broker::alerts::AlertRouter::new(
                std::sync::Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
                None,
                None,
            )),
            key_expiry_alert_days: 0,
            key_rotation_max_age_hours: None,
            anchor: None,
            anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
            anchor_targets: Arc::new(tessera_broker::anchoring::MemoryAnchorTargetStore::new()),
            secrets: None,
            rpc_policy: Arc::new(policy),
            egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
            rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
            agent_rate_limit_per_min: None,
            retention_days: 90,
            anchor_confirmations: 12,
            anchor_reorg_grace_secs: 300,
            default_ttl_seconds: 30,
            max_ttl_seconds: 3600,
            signing_key_history: Vec::new(),
            anchor_gap_threshold: 100,
            ledger_retention_days: 0,
            archive_dir: None,
            archive_interval_secs: 3600,
            archive_replica_dir: None,
            archive_retention_days: 0,
            alert_webhook_url: None,
            alert_webhook_token: None,
            alert_repeat_secs: 3600,
            alert_retry_secs: 60,
            gap_alerts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            tool_rate_limits: Vec::new(),
            demo_policy: Some(tessera_broker::policy::demo_policy()),
        })
    }

    let target = |rpc: &str| AnchorTarget {
        chain_id: 84532,
        rpc_url: rpc.into(),
        contract: "0x1111111111111111111111111111111111111111".into(),
        private_key: None,
        signer_history: Vec::new(),
    };

    // Strict policy: metadata/link-local/loopback targets are refused.
    let strict = service_with_policy(RpcPolicy::new(false, vec![])).await;
    assert!(strict
        .set_anchor_target("acme", target("http://169.254.169.254/latest/meta-data"))
        .await
        .is_err());
    assert!(strict
        .set_anchor_target("acme", target("http://127.0.0.1:8545"))
        .await
        .is_err());
    assert!(strict
        .set_anchor_target("acme", target("file:///etc/passwd"))
        .await
        .is_err());
    assert!(strict
        .set_anchor_target("acme", target("https://sepolia.base.org"))
        .await
        .is_ok());

    // Allowlist policy: only the named host is accepted.
    let listed =
        service_with_policy(RpcPolicy::new(false, vec!["rpc.my-org.example".into()])).await;
    assert!(listed
        .set_anchor_target("acme", target("https://rpc.my-org.example"))
        .await
        .is_ok());
    assert!(listed
        .set_anchor_target("acme", target("https://sepolia.base.org"))
        .await
        .is_err());
}

#[tokio::test]
async fn retention_runs_and_is_disabled_at_zero() {
    let svc = service(true).await;
    svc.authorize("acme", request(1)).await.unwrap();
    svc.authorize("acme", request(2)).await.unwrap();

    // days = 0 disables the sweep
    assert_eq!(svc.run_retention(0).await.unwrap(), (0, 0));
    // a 90-day window prunes nothing that just happened
    let (anchors, telemetry) = svc.run_retention(90).await.unwrap();
    assert_eq!((anchors, telemetry), (0, 0));
    // chain is untouched
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 2);
}

#[tokio::test]
async fn per_agent_rate_limit_throttles_only_the_noisy_agent() {
    let svc = service_with(true, Some(2)).await;

    let mut first = request(100);
    first.agent_id = "noisy-agent".into();
    assert!(matches!(
        svc.authorize("acme", first.clone()).await.unwrap().decision,
        Decision::Allow
    ));
    assert!(matches!(
        svc.authorize("acme", first.clone()).await.unwrap().decision,
        Decision::Allow
    ));
    let err = svc.authorize("acme", first).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Throttled(_)));
    assert_eq!(
        tessera_broker::http::status_for(&err),
        StatusCode::TOO_MANY_REQUESTS
    );

    // A different agent in the same tenant keeps its own budget.
    let mut quiet = request(100);
    quiet.agent_id = "quiet-agent".into();
    assert!(matches!(
        svc.authorize("acme", quiet).await.unwrap().decision,
        Decision::Allow
    ));
}

#[tokio::test]
async fn tool_rate_limits_throttle_one_resource_only() {
    let svc = service_opts(
        true,
        None,
        vec![("stripe:refunds.create".to_string(), 2)],
        3600,
    )
    .await;

    for _ in 0..2 {
        assert!(matches!(
            svc.authorize("acme", request(100)).await.unwrap().decision,
            Decision::Allow
        ));
    }
    let err = svc.authorize("acme", request(100)).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Throttled(_)));
    assert_eq!(
        tessera_broker::http::status_for(&err),
        StatusCode::TOO_MANY_REQUESTS
    );

    // Another resource is not affected by the refunds budget.
    let mut other = request(100);
    other.tool = "stripe.charges.create".into();
    assert!(svc.authorize("acme", other).await.is_ok());
}

#[tokio::test]
async fn credential_ttl_is_clamped_to_the_configured_maximum() {
    let svc = service_opts(true, None, Vec::new(), 5).await;
    let allowed = svc.authorize("acme", request(100)).await.unwrap();
    let credential = allowed.credential.expect("credential issued");
    assert_eq!(
        credential.ttl_seconds, 5,
        "default 30s must be clamped to max 5s"
    );
}

fn policy_with_limits(limits: tessera_broker::policy::PolicyLimits) -> Policy {
    Policy {
        // Replaces the builder's `acme-refunds` policy (upsert matches on id).
        id: "acme-refunds".into(),
        version: 1,
        name: "Limits".into(),
        grants: vec![ResourceGrant {
            resource: "*".into(),
            constraints: vec![],
            condition: None,
        }],
        fail_open: false,
        limits,
    }
}

#[tokio::test]
async fn policy_limits_cap_ttl_but_never_exceed_the_global_ceiling() {
    use tessera_broker::policy::PolicyLimits;

    // Policy asks for 5s while the service default is 30s and the ceiling is 3600s.
    let svc = service(true).await;
    svc.policies
        .upsert(
            "acme",
            policy_with_limits(PolicyLimits {
                max_ttl_seconds: Some(5),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let allowed = svc.authorize("acme", request(100)).await.unwrap();
    assert_eq!(allowed.credential.unwrap().ttl_seconds, 5);

    // A policy cannot raise the TTL above the global ceiling (5s here).
    let svc = service_opts(true, None, Vec::new(), 5).await;
    svc.policies
        .upsert(
            "acme",
            policy_with_limits(PolicyLimits {
                max_ttl_seconds: Some(999_999),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let allowed = svc.authorize("acme", request(100)).await.unwrap();
    assert_eq!(allowed.credential.unwrap().ttl_seconds, 5);
}

#[tokio::test]
async fn policy_agent_budget_throttles_without_affecting_other_policies() {
    use tessera_broker::policy::PolicyLimits;

    let svc = service(true).await;
    svc.policies
        .upsert(
            "acme",
            policy_with_limits(PolicyLimits {
                agent_rate_limit_per_min: Some(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    assert!(svc.authorize("acme", request(100)).await.is_ok());
    let err = svc.authorize("acme", request(100)).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Throttled(_)));

    // A tenant without the policy is unaffected (demo policy has no limits).
    assert!(svc.authorize("other", request(100)).await.is_ok());
}

#[tokio::test]
async fn signed_audit_export_verifies_and_detects_tampering() {
    let svc = service(true).await;
    let allowed = svc.authorize("acme", request(100)).await.unwrap();
    svc.record(
        "acme",
        RecordRequest {
            agent_id: "billing-agent".into(),
            receipt_id: allowed.receipt_id.clone(),
            result_hash: rh(0xde),
            status: Some("ok".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let bundle = svc.export_chain("acme", "billing-agent").await.unwrap();
    assert_eq!(bundle.manifest.receipt_count, 2);
    assert_eq!(bundle.manifest.chain_length, 2);
    assert_eq!(bundle.manifest.tenant, "acme");
    assert_eq!(bundle.manifest.agent, "billing-agent");
    assert_eq!(
        bundle.manifest.head.as_deref(),
        Some(bundle.receipts.last().unwrap().payload_hash.as_str())
    );
    assert!(bundle.verify().unwrap(), "a fresh export must verify");

    // Tampering with a receipt payload hash breaks linkage and the Merkle root.
    let mut tampered = bundle.clone();
    tampered.receipts[0].payload_hash = format!("0x{}", "11".repeat(32));
    assert!(!tampered.verify().unwrap());

    // Tampering with a manifest field breaks the signature.
    let mut tampered = bundle.clone();
    tampered.manifest.receipt_count = 1;
    assert!(!tampered.verify().unwrap());

    let mut tampered = bundle.clone();
    tampered.manifest.merkle_root = format!("0x{}", "22".repeat(32));
    assert!(!tampered.verify().unwrap());

    // Tampering with a receipt's contents (not just its hash) also fails verification.
    let mut tampered = bundle;
    tampered.receipts[0].receipt.intent_hash = "0x00".into();
    assert!(!tampered.verify().unwrap());
}

const TENANT_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

/// Service whose tenant has its own (encrypted) signing key configured.
async fn service_with_tenant_key() -> Arc<AuthorizeService> {
    use std::collections::HashMap;

    use tessera_broker::anchoring::{AnchorTarget, AnchorTargetStore, MemoryAnchorTargetStore};
    use tessera_broker::secrets::Envelope;

    let mut base = (*service(true).await).clone();
    let envelope = Envelope::from_hex(&"11".repeat(32)).unwrap();
    let targets = MemoryAnchorTargetStore::new();
    targets
        .set(
            "acme",
            AnchorTarget {
                chain_id: 84532,
                rpc_url: "http://127.0.0.1:8545".into(),
                contract: "0x0000000000000000000000000000000000000001".into(),
                private_key: Some(envelope.encrypt(TENANT_KEY).unwrap()),
                signer_history: Vec::new(),
            },
        )
        .await
        .unwrap();
    base.anchor_targets = Arc::new(targets);
    base.secrets = Some(Arc::new(envelope));
    let _: HashMap<String, String> = HashMap::new();
    Arc::new(base)
}

#[tokio::test]
async fn export_is_co_signed_by_the_tenant_key_when_configured() {
    let svc = service_with_tenant_key().await;
    svc.authorize("acme", request(100)).await.unwrap();

    let bundle = svc.export_chain("acme", "billing-agent").await.unwrap();
    let manifest = &bundle.manifest;
    let tenant_address = tessera_broker::receipt::ReceiptSigner::from_hex_or_random(
        Some(TENANT_KEY),
        84532,
        "0x0000000000000000000000000000000000000000",
    )
    .unwrap()
    .address_hex();
    assert_eq!(
        manifest.tenant_signer.as_deref(),
        Some(tenant_address.as_str())
    );
    assert!(manifest.tenant_signature.is_some());
    assert!(bundle.verify().unwrap(), "co-signed bundle must verify");

    // Claiming a different tenant signer breaks verification.
    let mut tampered = bundle.clone();
    tampered.manifest.tenant_signer = Some("0x000000000000000000000000000000000000dead".into());
    assert!(!tampered.verify().unwrap());

    // Dropping the signature but keeping the claimed signer is malformed.
    let mut tampered = bundle;
    tampered.manifest.tenant_signature = None;
    assert!(!tampered.verify().unwrap());
}

#[tokio::test]
async fn http_limits_reports_effective_posture() {
    use tessera_broker::policy::PolicyLimits;

    let svc = service(true).await;
    svc.policies
        .upsert(
            "acme",
            policy_with_limits(PolicyLimits {
                max_ttl_seconds: Some(15),
                tool_rate_limits: vec![("stripe:refunds.create".into(), 3)],
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let app = app_of(svc);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/limits")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(body["tenant"], "acme");
    assert_eq!(body["maxCredentialTtlSeconds"], 3600);
    assert_eq!(body["toolRateLimits"]["stripe:refunds.create"], 3);
    assert_eq!(body["policiesWithLimits"][0]["id"], "acme-refunds");
    assert_eq!(
        body["policiesWithLimits"][0]["limits"]["max_ttl_seconds"],
        15
    );
    assert!(body["strictEgress"].is_boolean());
    assert!(body["distributedRateLimiter"].is_boolean());
}

#[tokio::test]
async fn accepted_signers_covers_rotated_keys() {
    let mut base = (*service(true).await).clone();
    let current = base.signer.address_hex();
    base.signing_key_history = vec![
        "0x1111111111111111111111111111111111111111".into(),
        current.clone(), // duplicate of the current key must not repeat
    ];
    let svc = Arc::new(base);
    assert_eq!(
        svc.accepted_signers(),
        vec![
            current,
            "0x1111111111111111111111111111111111111111".to_string()
        ]
    );
}

#[tokio::test]
async fn http_tenant_export_and_signed_limits_verify() {
    let svc = service(true).await;
    for agent in ["agent-a", "agent-b"] {
        let mut req = request(100);
        req.agent_id = agent.into();
        svc.authorize("acme", req).await.unwrap();
    }
    let app = app_of(svc.clone());

    // Tenant-wide export over HTTP.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/export/tenant")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bundle: tessera_broker::export::TenantExportBundle = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(bundle.verify().unwrap());
    assert_eq!(bundle.manifest.agent_count, 2);

    // Signed limits snapshot over HTTP.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/limits?sign=true")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut document: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let snapshot: tessera_broker::export::SignedPayload = serde_json::from_value(
        document
            .as_object_mut()
            .unwrap()
            .remove("snapshot")
            .expect("snapshot present"),
    )
    .unwrap();
    assert!(tessera_broker::export::verify_signed_payload(
        tessera_broker::export::LIMITS_DOMAIN,
        &document,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());

    // Changing the payload invalidates the snapshot.
    document
        .as_object_mut()
        .unwrap()
        .insert("maxCredentialTtlSeconds".into(), serde_json::json!(1));
    assert!(!tessera_broker::export::verify_signed_payload(
        tessera_broker::export::LIMITS_DOMAIN,
        &document,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());
}

#[tokio::test]
async fn receipt_proof_links_a_receipt_to_an_anchor_root() {
    use tessera_broker::anchoring::AnchorRecord;

    let svc = service(true).await;
    for amount in [10, 20, 30] {
        svc.authorize("acme", request(amount)).await.unwrap();
    }

    // Anchor the current chain (as the scheduler would) and record the batch.
    let batch = svc.anchor_batch("acme", "billing-agent").await.unwrap();
    assert_eq!(batch.count, 3);
    svc.anchors
        .record(AnchorRecord {
            id: "anchor-1".into(),
            tenant: "acme".into(),
            agent: "billing-agent".into(),
            merkle_root: batch.root.clone(),
            count: batch.count,
            chain_id: 84532,
            contract: "0x0000000000000000000000000000000000000001".into(),
            tx_hash: Some("0xdeadbeef".into()),
            status: "confirmed".into(),
            block_number: Some(7),
            created_at: "2026-09-17T00:00:00Z".into(),
        })
        .await
        .unwrap();

    let chain = svc.chain.chain("acme", "billing-agent").await.unwrap();
    let target = &chain[1];

    // Looked up by payload hash.
    let proof = svc
        .receipt_proof("acme", "billing-agent", Some(&target.payload_hash), None)
        .await
        .unwrap();
    assert_eq!(proof["index"], 1);
    assert_eq!(proof["count"], 3);
    assert_eq!(proof["root"], batch.root);
    let root: [u8; 32] = {
        let raw = hex::decode(proof["root"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        raw.try_into().unwrap()
    };
    let leaf: [u8; 32] = {
        let raw = hex::decode(proof["receipt"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        raw.try_into().unwrap()
    };
    let siblings: Vec<[u8; 32]> = proof["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            hex::decode(v.as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    assert!(tessera_broker::merkle::verify(&siblings, root, leaf));
    // No tenant RPC target configured: the on-chain check is reported as not performed.
    assert_eq!(proof["onchain"]["checked"], false);

    // The same proof by index.
    let by_index = svc
        .receipt_proof("acme", "billing-agent", None, Some(1))
        .await
        .unwrap();
    assert_eq!(by_index["receipt"], proof["receipt"]);

    // Unknown receipt -> 404; both/neither parameters -> 400.
    assert!(matches!(
        svc.receipt_proof("acme", "billing-agent", Some("0x00"), None)
            .await
            .unwrap_err(),
        tessera_broker::BrokerError::NotFound(_)
    ));
    assert!(matches!(
        svc.receipt_proof("acme", "billing-agent", Some("0x00"), Some(0))
            .await
            .unwrap_err(),
        tessera_broker::BrokerError::Invalid(_)
    ));
}

#[tokio::test]
async fn tenant_key_rotation_records_history_and_keeps_old_signatures_valid() {
    use tessera_broker::anchoring::AnchorTarget;
    use tessera_broker::secrets::Envelope;

    let envelope = Arc::new(Envelope::from_hex(&"22".repeat(32)).unwrap());
    let mut base = (*service(true).await).clone();
    base.secrets = Some(envelope.clone());
    let svc = Arc::new(base);

    let key_a = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    let key_b = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    let address_a = tessera_broker::receipt::ReceiptSigner::from_hex_or_random(
        Some(key_a),
        84532,
        "0x0000000000000000000000000000000000000000",
    )
    .unwrap()
    .address_hex();

    let target = |key: &str| AnchorTarget {
        chain_id: 84532,
        rpc_url: "https://example.invalid".into(),
        contract: "0x0000000000000000000000000000000000000001".into(),
        private_key: Some(key.to_string()),
        signer_history: Vec::new(),
    };

    // Configure key A and export (co-signed by A).
    svc.set_anchor_target("acme", target(key_a)).await.unwrap();
    svc.authorize("acme", request(100)).await.unwrap();
    let export_a = svc.export_chain("acme", "billing-agent").await.unwrap();
    assert_eq!(
        export_a.manifest.tenant_signer.as_deref(),
        Some(address_a.as_str())
    );
    assert!(export_a.verify().unwrap());

    // Rotate to key B: A's address lands in the history automatically.
    svc.set_anchor_target("acme", target(key_b)).await.unwrap();
    let signers = svc.accepted_tenant_signers("acme").await.unwrap();
    assert_eq!(signers.len(), 2);
    assert!(signers.iter().any(|s| s.eq_ignore_ascii_case(&address_a)));

    // The pre-rotation export still verifies; the accepted set includes the old key.
    assert!(export_a.verify().unwrap());
    assert!(signers
        .iter()
        .any(|s| s.eq_ignore_ascii_case(export_a.manifest.tenant_signer.as_deref().unwrap())));

    // New exports are co-signed by B only.
    let export_b = svc.export_chain("acme", "billing-agent").await.unwrap();
    assert_ne!(
        export_b.manifest.tenant_signer,
        export_a.manifest.tenant_signer
    );
    assert!(export_b.verify().unwrap());
}

#[tokio::test]
async fn anchor_gaps_report_unanchored_growth() {
    use tessera_broker::anchoring::AnchorRecord;

    let svc = service(true).await;
    for agent in ["anchored-agent", "quiet-agent", "drifting-agent"] {
        let mut req = request(100);
        req.agent_id = agent.into();
        svc.authorize("acme", req).await.unwrap();
    }
    // Grow two chains past their anchor point.
    for _ in 0..2 {
        let mut req = request(100);
        req.agent_id = "drifting-agent".into();
        svc.authorize("acme", req).await.unwrap();
    }
    let batch = svc.anchor_batch("acme", "anchored-agent").await.unwrap();
    svc.anchors
        .record(AnchorRecord {
            id: "a1".into(),
            tenant: "acme".into(),
            agent: "anchored-agent".into(),
            merkle_root: batch.root,
            count: batch.count,
            chain_id: 84532,
            contract: "0x0000000000000000000000000000000000000001".into(),
            tx_hash: Some("0xdead".into()),
            status: "confirmed".into(),
            block_number: Some(1),
            created_at: "2026-09-17T00:00:00Z".into(),
        })
        .await
        .unwrap();

    let gaps = svc.anchor_gaps("acme").await.unwrap();
    let by_agent: std::collections::HashMap<_, _> = gaps
        .iter()
        .map(|gap| (gap["agent"].as_str().unwrap().to_string(), gap.clone()))
        .collect();

    // Fully anchored: absent from the report.
    assert!(!by_agent.contains_key("anchored-agent"));
    // Never anchored: gap equals the chain length.
    assert_eq!(by_agent["quiet-agent"]["gap"], 1);
    assert_eq!(by_agent["quiet-agent"]["lastAnchoredCount"], 0);
    // Anchored then grew: gap is the un-anchored suffix.
    assert_eq!(by_agent["drifting-agent"]["gap"], 3);
    assert_eq!(by_agent["drifting-agent"]["chainLength"], 3);
    // Sorted by gap descending.
    assert_eq!(gaps[0]["agent"], "drifting-agent");
}

#[tokio::test]
async fn scheduled_archive_writes_a_verifiable_file() {
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("tessera-archive-{}-{}", std::process::id(), {
                unique_suffix()
            }));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let svc = service(true).await;
    let dir = Dir::new();

    // No agents yet: nothing to archive.
    assert!(svc
        .write_tenant_archive("acme", &dir.0)
        .await
        .unwrap()
        .is_none());

    let mut req = request(100);
    req.agent_id = "archive-agent".into();
    svc.authorize("acme", req).await.unwrap();

    let path = svc
        .write_tenant_archive("acme", &dir.0)
        .await
        .unwrap()
        .expect("archive written");
    assert!(path.exists());
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic");

    // The written archive contains a verifiable agent bundle.
    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    let mut verified = false;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry
            .path()
            .unwrap()
            .to_string_lossy()
            .starts_with("agents/")
        {
            let mut content = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut content).unwrap();
            let bundle: tessera_broker::export::ExportBundle =
                serde_json::from_slice(&content).unwrap();
            assert!(bundle.verify().unwrap());
            verified = true;
        }
    }
    assert!(verified);
}

#[tokio::test]
async fn per_key_budgets_isolate_integrations() {
    use tessera_broker::auth::ApiKeyStore;
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (noisy, noisy_key) = keys
        .create(
            "acme",
            "noisy-integration",
            None,
            tessera_broker::auth::NewKeyOptions {
                rate_limit_per_min: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_quiet, quiet_key) = keys
        .create("acme", "quiet-integration", None, Default::default())
        .await
        .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: false,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let call = |key: &str| {
        let app = app.clone();
        let key = key.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .header("x-api-key", key)
                    .body(Body::from(
                        serde_json::json!({
                            "agentId": "billing-agent",
                            "userId": "u1",
                            "tool": "stripe.refunds.create",
                            "intent": "refund",
                            "args": {"charge": "ch_1", "amount": 100}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    assert_eq!(call(&noisy_key).await, StatusCode::OK);
    assert_eq!(call(&noisy_key).await, StatusCode::OK);
    assert_eq!(call(&noisy_key).await, StatusCode::TOO_MANY_REQUESTS);

    // A different key in the same tenant is unaffected.
    assert_eq!(call(&quiet_key).await, StatusCode::OK);
    assert_eq!(noisy.rate_limit_per_min, Some(2));

    // The posture endpoint reports the caller's own key budget.
    let (_limited, limited_key) = keys
        .create(
            "acme",
            "limited",
            None,
            tessera_broker::auth::NewKeyOptions {
                rate_limit_per_min: Some(5),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/limits")
                .header("x-api-key", limited_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["keyRateLimitPerMin"], 5);
}

#[tokio::test]
async fn key_scopes_restrict_resources_and_agents() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope};
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (_scoped, stripe_key) = keys
        .create(
            "acme",
            "stripe-integration",
            None,
            tessera_broker::auth::NewKeyOptions {
                scope: KeyScope {
                    resources: vec!["stripe:*".into()],
                    agents: vec!["billing-agent".into()],
                    capabilities: vec![],
                    proxy_paths: vec![],
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_open, open_key) = keys
        .create("acme", "unrestricted", None, Default::default())
        .await
        .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: false,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let call = |key: &str, agent: &str, tool: &str| {
        let app = app.clone();
        let body = serde_json::json!({
            "agentId": agent,
            "userId": "u1",
            "tool": tool,
            "intent": "do the thing",
            "args": {"charge": "ch_1", "amount": 10}
        })
        .to_string();
        let key = key.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .header("x-api-key", key)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    // Inside the scope.
    assert_eq!(
        call(&stripe_key, "billing-agent", "stripe.refunds.create").await,
        StatusCode::OK
    );
    // Resource outside the scope is denied before policy evaluation.
    assert_eq!(
        call(&stripe_key, "billing-agent", "aws.sts.assume_role").await,
        StatusCode::FORBIDDEN
    );
    // Agent outside the scope is denied.
    assert_eq!(
        call(&stripe_key, "other-agent", "stripe.refunds.create").await,
        StatusCode::FORBIDDEN
    );
    // An unscoped key is unaffected.
    assert_eq!(
        call(&open_key, "other-agent", "aws.sts.assume_role").await,
        StatusCode::OK
    );

    // The posture endpoint reports the caller's scope.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/limits")
                .header("x-api-key", stripe_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["keyScope"]["resources"][0], "stripe:*");
    assert_eq!(body["keyScope"]["agents"][0], "billing-agent");
}

#[tokio::test]
async fn archive_replication_copies_and_verifies_the_file() {
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "tessera-replica-{tag}-{}-{}",
                std::process::id(),
                { unique_suffix() }
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let primary = Dir::new("primary");
    let replica = Dir::new("replica");

    let base = (*service(true).await).clone();
    let mut base = base;
    base.archive_replica_dir = Some(replica.0.to_string_lossy().to_string());
    let svc = Arc::new(base);

    let mut req = request(100);
    req.agent_id = "replica-agent".into();
    svc.authorize("acme", req).await.unwrap();

    let path = svc
        .write_tenant_archive("acme", &primary.0)
        .await
        .unwrap()
        .unwrap();
    let name = path.file_name().unwrap();
    let replica_path = replica.0.join(name);
    assert!(replica_path.exists(), "replica must exist");
    let original = std::fs::read(&path).unwrap();
    let copy = std::fs::read(&replica_path).unwrap();
    assert_eq!(original, copy, "replica must be byte-identical");

    // An unwritable replica location must not fail the primary archive write.
    let mut broken = (*svc).clone();
    broken.archive_replica_dir = Some("/dev/null/not-a-dir".to_string());
    let svc_broken = Arc::new(broken);
    let again = svc_broken
        .write_tenant_archive("acme", &primary.0)
        .await
        .expect("primary archive still succeeds")
        .expect("archive written");
    assert!(again.exists());
}

#[tokio::test]
async fn gap_alerts_are_signed_deduplicated_and_verify_offline() {
    use std::sync::Mutex as StdMutex;

    use axum::extract::State;

    #[derive(Clone)]
    struct Sink(Arc<StdMutex<Vec<serde_json::Value>>>);

    async fn handler(
        State(sink): State<Sink>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let token_ok = headers
            .get("x-tessera-alert-token")
            .and_then(|v| v.to_str().ok())
            .map(|value| value == "s3cret")
            .unwrap_or(false);
        if !token_ok {
            return StatusCode::UNAUTHORIZED;
        }
        sink.0.lock().unwrap().push(body);
        StatusCode::OK
    }

    let sink = Sink(Arc::new(StdMutex::new(Vec::new())));
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(handler))
        .with_state(sink.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("http://{addr}/hook");

    let mut base = (*service(true).await).clone();
    base.alert_router = Arc::new(tessera_broker::alerts::AlertRouter::new(
        Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
        Some(url),
        Some("s3cret".into()),
    ));
    base.alert_repeat_secs = 3600;
    base.alert_retry_secs = 0;
    base.anchor_gap_threshold = 1;
    let svc = Arc::new(base);

    let mut req = request(100);
    req.agent_id = "alert-agent".into();
    svc.authorize("acme", req).await.unwrap();

    assert!(svc
        .alert_anchor_gap("acme", "alert-agent", 3, 4)
        .await
        .unwrap());
    // Repeat within the suppression window is skipped.
    assert!(!svc
        .alert_anchor_gap("acme", "alert-agent", 3, 4)
        .await
        .unwrap());

    // A failed delivery is retried after the (short) retry interval, not the repeat window.
    let mut failing = (*svc).clone();
    failing.alert_router = Arc::new(tessera_broker::alerts::AlertRouter::new(
        Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
        Some("http://127.0.0.1:1/hook".into()),
        None,
    ));
    failing.alert_retry_secs = 0;
    let failing = Arc::new(failing);
    assert!(!failing
        .alert_anchor_gap("acme", "alert-agent", 3, 4)
        .await
        .unwrap());
    assert!(!failing
        .alert_anchor_gap("acme", "alert-agent", 3, 4)
        .await
        .unwrap());

    let delivered = sink.0.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1, "exactly one alert");

    // The delivered payload verifies offline against the broker key and the domain tag.
    let mut value = delivered[0].clone();
    let snapshot: tessera_broker::export::SignedPayload = serde_json::from_value(
        value
            .as_object_mut()
            .unwrap()
            .remove("snapshot")
            .expect("snapshot present"),
    )
    .unwrap();
    assert_eq!(value["event"], "anchor.gap");
    assert_eq!(value["gap"], 3);
    assert!(tessera_broker::export::verify_signed_payload(
        tessera_broker::export::ALERT_DOMAIN,
        &value,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());

    // Tampering invalidates it.
    value
        .as_object_mut()
        .unwrap()
        .insert("gap".into(), serde_json::json!(1));
    assert!(!tessera_broker::export::verify_signed_payload(
        tessera_broker::export::ALERT_DOMAIN,
        &value,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());
}

#[tokio::test]
async fn expired_keys_stop_authenticating() {
    use tessera_broker::auth::{ApiKeyStore, NewKeyOptions};
    use tessera_broker::MemoryApiKeyStore;

    let store = MemoryApiKeyStore::new();
    let (_expiring, expiring_key) = store
        .create(
            "acme",
            "short-lived",
            None,
            NewKeyOptions {
                expires_at: Some(
                    (chrono::Utc::now() + chrono::Duration::seconds(30))
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_expired, expired_key) = store
        .create(
            "acme",
            "already-lapsed",
            None,
            NewKeyOptions {
                expires_at: Some(
                    (chrono::Utc::now() - chrono::Duration::seconds(1))
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_unparseable, bad_key) = store
        .create(
            "acme",
            "bad-expiry",
            None,
            NewKeyOptions {
                expires_at: Some("not-a-date".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(store.authenticate(&expiring_key).await.unwrap().is_some());
    assert!(store.authenticate(&expired_key).await.unwrap().is_none());
    assert!(
        store.authenticate(&bad_key).await.unwrap().is_none(),
        "an unparseable expiry must fail closed"
    );
}

#[tokio::test]
async fn http_key_creation_accepts_ttl_and_expiry() {
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "name": "ttl-key", "ttlSeconds": 3600 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let expires_at = body["record"]["expiresAt"].as_str().expect("expiresAt set");
    let parsed = chrono::DateTime::parse_from_rfc3339(expires_at).unwrap();
    assert!(parsed.with_timezone(&chrono::Utc) > chrono::Utc::now());

    // A past expiry is rejected outright.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": "past",
                        "expiresAt": "2020-01-01T00:00:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_alert_routing_prefers_the_tenant_webhook() {
    use std::sync::Mutex as StdMutex;

    use axum::extract::State;
    use tessera_broker::alerts::{AlertTarget, AlertTargetStore, MemoryAlertTargetStore};

    #[derive(Clone)]
    struct Sink(Arc<StdMutex<Vec<serde_json::Value>>>);

    async fn handler(
        State(sink): State<Sink>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        sink.0.lock().unwrap().push(body);
        StatusCode::OK
    }

    let sink = Sink(Arc::new(StdMutex::new(Vec::new())));
    let app = axum::Router::new()
        .route("/tenant-hook", axum::routing::post(handler))
        .with_state(sink.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let store = Arc::new(MemoryAlertTargetStore::new());
    store
        .set(
            "acme",
            AlertTarget {
                url: format!("http://{addr}/tenant-hook"),
                token: Some("tenant-secret".into()),
                events: vec!["anchor.gap".into()],
                auto_ack_below: None,
            },
        )
        .await
        .unwrap();

    let mut base = (*service(true).await).clone();
    base.alert_router = Arc::new(tessera_broker::alerts::AlertRouter::new(
        store.clone(),
        // A global fallback that would also work, to prove routing prefers the tenant.
        Some(format!("http://{addr}/tenant-hook")),
        None,
    ));
    base.alert_retry_secs = 0;
    let svc = Arc::new(base);

    assert!(svc.alert_anchor_gap("acme", "agent-1", 5, 6).await.unwrap());
    let delivered = sink.0.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0]["event"], "anchor.gap");
    assert_eq!(delivered[0]["tenant"], "acme");

    // A tenant with no target for this event falls back to the global webhook.
    assert!(svc
        .alert_anchor_gap("other", "agent-1", 5, 6)
        .await
        .unwrap());
    assert_eq!(sink.0.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn alert_config_rejects_private_urls_and_redacts_tokens() {
    use tessera_broker::alerts::AlertTarget;
    use tessera_broker::netguard::RpcPolicy;
    use tessera_broker::secrets::Envelope;

    let mut base = (*service(true).await).clone();
    base.secrets = Some(Arc::new(Envelope::from_hex(&"33".repeat(32)).unwrap()));
    base.rpc_policy = Arc::new(RpcPolicy::new(false, vec![])); // private ranges blocked
    let svc = Arc::new(base);

    // Localhost is rejected for tenant-supplied alert URLs (SSRF policy).
    let err = svc
        .set_alert_target(
            "acme",
            AlertTarget {
                url: "http://127.0.0.1:9999/hook".into(),
                token: None,
                events: vec![],
                auto_ack_below: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));

    // A public URL is accepted, and the token is encrypted at rest but readable back.
    let stored = svc
        .set_alert_target(
            "acme",
            AlertTarget {
                url: "https://hooks.example.com/tessera".into(),
                token: Some("super-secret".into()),
                events: vec!["anchor.gap".into(), "key.expiring".into()],
                auto_ack_below: None,
            },
        )
        .await
        .unwrap();
    let raw = stored.token.as_deref().unwrap();
    assert!(
        tessera_broker::secrets::is_encrypted(raw),
        "token at rest must be encrypted"
    );
    assert!(!raw.contains("super-secret"));

    let readback = svc.alert_target("acme").await.unwrap().unwrap();
    assert_eq!(readback.token.as_deref(), Some("super-secret"));
    assert_eq!(readback.url, "https://hooks.example.com/tessera");

    assert!(svc.alert_router.delete_target("acme").await.unwrap());
    assert!(svc.alert_target("acme").await.unwrap().is_none());
}

#[tokio::test]
async fn key_renewal_rotates_the_secret_in_place() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope, NewKeyOptions};
    use tessera_broker::MemoryApiKeyStore;

    let store = MemoryApiKeyStore::new();
    let (record, original_key) = store
        .create(
            "acme",
            "ci-integration",
            None,
            NewKeyOptions {
                rate_limit_per_min: Some(4),
                scope: KeyScope {
                    resources: vec!["stripe:*".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    use tessera_broker::auth::MutateOutcome;
    let (renewed, new_key) = match store
        .renew(
            "acme",
            &record.id,
            Some("2099-01-01T00:00:00Z".into()),
            None,
        )
        .await
        .unwrap()
    {
        MutateOutcome::Done(result) => result,
        other => panic!("expected rotation, got {other:?}"),
    };

    // Same identity, scope and budget; new secret; history preserved.
    assert_eq!(renewed.id, record.id);
    assert_eq!(renewed.name, "ci-integration");
    assert_eq!(renewed.rate_limit_per_min, Some(4));
    assert_eq!(renewed.scope.resources, vec!["stripe:*".to_string()]);
    assert_eq!(renewed.rotation_count, 1);
    assert!(renewed.rotated_at.is_some());
    assert_eq!(renewed.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
    assert_ne!(new_key, original_key);

    // The new secret works; the old one is dead immediately.
    let authenticated = store
        .authenticate(&new_key)
        .await
        .unwrap()
        .expect("new key live");
    assert_eq!(authenticated.id, record.id);
    assert!(store.authenticate(&original_key).await.unwrap().is_none());

    // Renewing an unknown or revoked key reports failure rather than minting one.
    assert_eq!(
        store
            .renew("acme", "key_missing", None, None)
            .await
            .unwrap(),
        MutateOutcome::NotFound
    );
    assert_eq!(
        store.revoke("acme", &record.id, None).await.unwrap(),
        MutateOutcome::Done(())
    );
    assert_eq!(
        store.renew("acme", &record.id, None, None).await.unwrap(),
        MutateOutcome::NotFound
    );
}

#[tokio::test]
async fn http_key_renewal_returns_the_new_secret_once() {
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "name": "renewable", "ttlSeconds": 3600 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let created_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created_body["record"]["id"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/keys/{id}/renew"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "ttlSeconds": 7200 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["record"]["rotationCount"], 1);
    let new_key = body["key"].as_str().unwrap();

    // Unknown id -> 404.
    let missing = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys/key_missing/renew")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    // The returned secret authenticates (checked via a protected call).
    use tessera_broker::auth::ApiKeyStore;
    assert!(keys.authenticate(new_key).await.unwrap().is_some());
}

#[tokio::test]
async fn import_replays_a_signed_bundle_idempotently() {
    // Source broker produces a real chain and exports it.
    let source = service(true).await;
    for amount in [10, 20, 30] {
        source.authorize("acme", request(amount)).await.unwrap();
    }
    let bundle = source.export_chain("acme", "billing-agent").await.unwrap();
    assert!(bundle.verify().unwrap());

    // Destination broker (fresh store) imports the bundle.
    let target = service(true).await;
    let summary = target.import_chain("acme", &bundle).await.unwrap();
    assert_eq!(summary["imported"], 3);
    assert_eq!(summary["skipped"], 0);

    let imported = target.chain.chain("acme", "billing-agent").await.unwrap();
    let original = source.chain.chain("acme", "billing-agent").await.unwrap();
    assert_eq!(imported.len(), original.len());
    for (local, expected) in imported.iter().zip(original.iter()) {
        assert_eq!(local.payload_hash, expected.payload_hash);
    }
    // The imported chain verifies end to end (signatures + linkage).
    let domain = *target.signer.domain();
    let verification = tessera_broker::verify::verify_chain(&domain, &imported).unwrap();
    assert!(verification.valid);

    // Replaying the same bundle is a no-op.
    let again = target.import_chain("acme", &bundle).await.unwrap();
    assert_eq!(again["imported"], 0);
    assert_eq!(again["skipped"], 3);

    // Completing a partially restored chain works: wipe, import the first receipt, then all.
    let partial = service(true).await;
    let first_only = tessera_broker::export::ExportBundle {
        manifest: bundle.manifest.clone(),
        receipts: bundle.receipts[..1].to_vec(),
    };
    // A truncated bundle no longer matches its manifest root, so it is refused.
    assert!(matches!(
        partial.import_chain("acme", &first_only).await.unwrap_err(),
        tessera_broker::BrokerError::Invalid(_)
    ));
    let first_two = tessera_broker::export::ExportBundle {
        manifest: source
            .export_chain("acme", "billing-agent")
            .await
            .unwrap()
            .manifest,
        receipts: bundle.receipts[..2].to_vec(),
    };
    assert!(partial.import_chain("acme", &first_two).await.is_err());
    let full_again = partial.import_chain("acme", &bundle).await.unwrap();
    assert_eq!(full_again["imported"], 3);
}

#[tokio::test]
async fn import_rejects_forged_or_foreign_bundles() {
    let source = service(true).await;
    source.authorize("acme", request(100)).await.unwrap();
    let bundle = source.export_chain("acme", "billing-agent").await.unwrap();

    let target = service(true).await;

    // Wrong tenant.
    assert!(matches!(
        target.import_chain("other", &bundle).await.unwrap_err(),
        tessera_broker::BrokerError::Denied(_)
    ));

    // Tampered receipt content breaks the bundle root.
    let mut tampered = bundle.clone();
    tampered.receipts[0].receipt.intent_hash = "0x00".into();
    assert!(matches!(
        target.import_chain("acme", &tampered).await.unwrap_err(),
        tessera_broker::BrokerError::Invalid(_)
    ));

    // A bundle signed by an unknown key is refused even when internally consistent.
    let foreign = AuthorizeService {
        signer: Arc::new(
            tessera_broker::receipt::ReceiptSigner::from_hex_or_random(
                Some("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
                84532,
                "0x0000000000000000000000000000000000000000",
            )
            .unwrap(),
        ),
        ..(*source.clone()).clone()
    };
    let foreign_bundle = foreign.export_chain("acme", "billing-agent").await.unwrap();
    assert_eq!(foreign_bundle.manifest.signer, foreign.signer.address_hex());
    assert!(matches!(
        target
            .import_chain("acme", &foreign_bundle)
            .await
            .unwrap_err(),
        tessera_broker::BrokerError::Denied(_)
    ));
}

#[tokio::test]
async fn alert_acks_suppress_repeats_until_the_condition_worsens() {
    use std::sync::Mutex as StdMutex;

    use axum::extract::State;

    #[derive(Clone)]
    struct Sink(Arc<StdMutex<Vec<serde_json::Value>>>);

    async fn handler(
        State(sink): State<Sink>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        sink.0.lock().unwrap().push(body);
        StatusCode::OK
    }

    let sink = Sink(Arc::new(StdMutex::new(Vec::new())));
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(handler))
        .with_state(sink.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut base = (*service(true).await).clone();
    base.alert_router = Arc::new(tessera_broker::alerts::AlertRouter::new(
        Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
        Some(format!("http://{addr}/hook")),
        None,
    ));
    base.alert_retry_secs = 0;
    base.anchor_gap_threshold = 1;
    let svc = Arc::new(base);

    // First alert fires.
    assert!(svc.alert_anchor_gap("acme", "agent-1", 5, 6).await.unwrap());
    // Acknowledged at severity 5: the same (and better) conditions stay quiet.
    svc.ack_alert("acme", "anchor.gap", "agent-1", 5)
        .await
        .unwrap();
    assert!(!svc.alert_anchor_gap("acme", "agent-1", 5, 6).await.unwrap());
    assert!(!svc.alert_anchor_gap("acme", "agent-1", 4, 5).await.unwrap());
    // Worse fires again, and the new alert carries the condition value.
    assert!(svc
        .alert_anchor_gap("acme", "agent-1", 9, 10)
        .await
        .unwrap());
    let delivered = sink.0.lock().unwrap().clone();
    assert_eq!(delivered.len(), 2);
    assert_eq!(delivered[1]["conditionValue"], 9);

    // The ack listing exposes what is acknowledged.
    let acks = svc.alert_acks.list("acme").await.unwrap();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].value, 5);

    // A different agent is unaffected by the ack.
    assert!(svc.alert_anchor_gap("acme", "agent-2", 5, 6).await.unwrap());
}

#[tokio::test]
async fn http_alert_ack_uses_the_current_severity_by_default() {
    use tessera_broker::anchoring::AnchorRecord;

    let svc = service(true).await;
    let mut req = request(100);
    req.agent_id = "gap-agent".into();
    svc.authorize("acme", req).await.unwrap();
    let batch = svc.anchor_batch("acme", "gap-agent").await.unwrap();
    svc.anchors
        .record(AnchorRecord {
            id: "a1".into(),
            tenant: "acme".into(),
            agent: "gap-agent".into(),
            merkle_root: batch.root,
            count: batch.count,
            chain_id: 84532,
            contract: "0x0000000000000000000000000000000000000001".into(),
            tx_hash: None,
            status: "confirmed".into(),
            block_number: None,
            created_at: "2026-09-17T00:00:00Z".into(),
        })
        .await
        .unwrap();
    // Grow the chain so there is a gap to acknowledge.
    let mut req = request(100);
    req.agent_id = "gap-agent".into();
    svc.authorize("acme", req).await.unwrap();

    let app = app_of(svc);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/alerts/ack")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({ "event": "anchor.gap", "dedupKey": "gap-agent" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["ack"]["value"], 1, "ack defaults to the current gap");

    // Listing shows it, and an event we cannot compute a severity for needs an explicit value.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/alerts/ack")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({ "event": "key.expiring", "dedupKey": "key_1" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn import_report_describes_drift_without_writing() {
    let source = service(true).await;
    for amount in [10, 20] {
        source.authorize("acme", request(amount)).await.unwrap();
    }
    let bundle = source.export_chain("acme", "billing-agent").await.unwrap();

    // Fresh broker: everything is missing, nothing written.
    let target = service(true).await;
    let report = target.import_report("acme", &bundle).await.unwrap();
    assert_eq!(report["bundleReceipts"], 2);
    assert_eq!(report["existing"], 0);
    assert_eq!(report["matched"], 0);
    assert_eq!(report["missing"], 2);
    assert_eq!(report["wouldImport"], 2);
    assert_eq!(report["divergent"], serde_json::Value::Null);
    assert_eq!(report["verified"], true);
    assert_eq!(
        target.chain.len("acme", "billing-agent").await.unwrap(),
        0,
        "a dry run must not write"
    );

    // After importing, everything matches.
    target.import_chain("acme", &bundle).await.unwrap();
    let report = target.import_report("acme", &bundle).await.unwrap();
    assert_eq!(report["matched"], 2);
    assert_eq!(report["missing"], 0);
    assert_eq!(report["wouldImport"], 0);
    assert_eq!(report["localHead"], report["bundleHead"]);

    // A local chain that diverges is reported at the first differing index.
    let mut local = (*target).clone();
    local.chain = Arc::new(tessera_broker::chain::MemoryChainStore::new());
    let local = Arc::new(local);
    let mut first_only = bundle.clone();
    first_only.receipts.truncate(1);
    // (Append a receipt from a different chain to create divergence.)
    let other = service(true).await;
    other.authorize("acme", request(999)).await.unwrap();
    let foreign = other.export_chain("acme", "billing-agent").await.unwrap();
    local
        .chain
        .append("acme", "billing-agent", foreign.receipts[0].clone())
        .await
        .unwrap();
    let report = local.import_report("acme", &bundle).await.unwrap();
    assert_eq!(report["divergent"]["index"], 0);
    assert!(report["divergent"]["local"].is_string());
    // And the import path refuses rather than overwriting.
    assert!(matches!(
        local.import_chain("acme", &bundle).await.unwrap_err(),
        tessera_broker::BrokerError::Invalid(_)
    ));
}

#[tokio::test]
async fn auto_ack_policy_suppresses_low_severity_alerts() {
    use std::sync::Mutex as StdMutex;

    use axum::extract::State;
    use tessera_broker::alerts::{
        AlertRouter, AlertTarget, AlertTargetStore, MemoryAlertTargetStore,
    };

    #[derive(Clone)]
    struct Sink(Arc<StdMutex<Vec<serde_json::Value>>>);

    async fn handler(
        State(sink): State<Sink>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        sink.0.lock().unwrap().push(body);
        StatusCode::OK
    }

    let sink = Sink(Arc::new(StdMutex::new(Vec::new())));
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(handler))
        .with_state(sink.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let store = Arc::new(MemoryAlertTargetStore::new());
    store
        .set(
            "acme",
            AlertTarget {
                url: format!("http://{addr}/hook"),
                token: None,
                events: vec![],
                // Only severity > 5 pages anyone.
                auto_ack_below: Some(5),
            },
        )
        .await
        .unwrap();

    let mut base = (*service(true).await).clone();
    base.alert_router = Arc::new(AlertRouter::new(store, None, None));
    base.alert_retry_secs = 0;
    base.anchor_gap_threshold = 1;
    let svc = Arc::new(base);

    // Below the threshold: counted, not delivered.
    assert!(!svc.alert_anchor_gap("acme", "agent-1", 3, 4).await.unwrap());
    assert!(sink.0.lock().unwrap().is_empty());
    // Above the threshold: delivered.
    assert!(svc.alert_anchor_gap("acme", "agent-1", 6, 7).await.unwrap());
    assert_eq!(sink.0.lock().unwrap().len(), 1);

    // A tenant without a policy is unaffected by the other tenant's auto-ack.
    assert!(svc.alert_anchor_gap("other", "agent-1", 1, 2).await.is_ok());
}

#[tokio::test]
async fn key_event_ledger_links_creation_renewal_and_revocation() {
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys: keys.clone(),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    // Create -> renew -> revoke through the API.
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "name": "ledger-key", "ttlSeconds": 3600 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let created_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created_body["record"]["id"].as_str().unwrap().to_string();

    let renewed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/keys/{id}/renew"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "ttlSeconds": 7200 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(renewed.status(), StatusCode::OK);

    let revoked = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/keys/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);

    // The ledger records all three, hash-linked and signed, and verifies.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/key-events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let log: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(log["count"], 3);
    assert_eq!(log["verified"], true);
    assert_eq!(log["items"][0]["kind"], "key.created");
    assert_eq!(log["items"][1]["kind"], "key.renewed");
    assert_eq!(log["items"][2]["kind"], "key.revoked");
    assert!(log["items"][0]["prevHash"].is_null());
    assert_eq!(log["items"][1]["prevHash"], log["items"][0]["eventHash"]);

    // Tampering with a recorded detail invalidates the log.
    let events: Vec<tessera_broker::key_events::KeyEvent> =
        serde_json::from_value(log["items"].clone()).unwrap();
    assert!(tessera_broker::key_events::verify_chain(&events));
    let mut tampered = events.clone();
    tampered[1].details = serde_json::json!({ "rotationCount": 99 });
    assert!(!tessera_broker::key_events::verify_chain(&tampered));
}

#[tokio::test]
async fn chain_drift_is_detected_against_the_archive_checkpoint() {
    let svc = service(true).await;
    for amount in [10, 20, 30] {
        svc.authorize("acme", request(amount)).await.unwrap();
    }
    let dir = std::env::temp_dir().join(format!("tessera-drift-{}-{}", std::process::id(), {
        unique_suffix()
    }));
    std::fs::create_dir_all(&dir).unwrap();

    // Archive writes checkpoints for every agent.
    svc.write_tenant_archive("acme", &dir)
        .await
        .unwrap()
        .unwrap();
    assert!(svc.chain_drift("acme").await.unwrap().is_empty());

    // Grow the chain: still no drift (checkpoints anchor the past, not the future).
    svc.authorize("acme", request(40)).await.unwrap();
    assert!(svc.chain_drift("acme").await.unwrap().is_empty());

    // Rewrite history: a different receipt at index 0.
    let mut rewritten = (*svc).clone();
    let store: Arc<dyn tessera_broker::chain::ChainStore> =
        Arc::new(tessera_broker::chain::MemoryChainStore::new());
    rewritten.chain = store.clone();
    let other = service(true).await;
    for amount in [123, 124, 125] {
        other.authorize("acme", request(amount)).await.unwrap();
    }
    let foreign = other.export_chain("acme", "billing-agent").await.unwrap();
    for entry in &foreign.receipts {
        store
            .append("acme", "billing-agent", entry.clone())
            .await
            .unwrap();
    }
    let rewritten = Arc::new(rewritten);
    let drift = rewritten.chain_drift("acme").await.unwrap();
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].kind, "rewritten");

    // Lost receipts: a shorter chain than checkpointed.
    let mut truncated = (*svc).clone();
    truncated.chain = foreign_store_empty();
    let truncated = Arc::new(truncated);
    let drift = truncated.chain_drift("acme").await.unwrap();
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].kind, "missing");
    assert_eq!(drift[0].severity, 3);

    let _ = std::fs::remove_dir_all(&dir);
}

fn foreign_store_empty() -> Arc<dyn tessera_broker::chain::ChainStore> {
    Arc::new(tessera_broker::chain::MemoryChainStore::new())
}

#[tokio::test]
async fn integrity_report_summarizes_the_tenant_posture() {
    use tessera_broker::anchoring::AnchorRecord;
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    for amount in [10, 20] {
        svc.authorize("acme", request(amount)).await.unwrap();
    }
    let batch = svc.anchor_batch("acme", "billing-agent").await.unwrap();
    svc.anchors
        .record(AnchorRecord {
            id: "a1".into(),
            tenant: "acme".into(),
            agent: "billing-agent".into(),
            merkle_root: batch.root,
            count: batch.count,
            chain_id: 84532,
            contract: "0x0000000000000000000000000000000000000001".into(),
            tx_hash: Some("0xdead".into()),
            status: "confirmed".into(),
            block_number: Some(1),
            created_at: "2026-09-17T00:00:00Z".into(),
        })
        .await
        .unwrap();
    // A second, unanchored agent.
    let mut req = request(30);
    req.agent_id = "quiet-agent".into();
    svc.authorize("acme", req).await.unwrap();
    svc.append_key_event(
        "acme",
        "key.created",
        &{
            let mut record = tessera_broker::auth::new_record("acme", "ci", "tsk_x");
            record.id = "key_1".into();
            record
        },
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: Arc::new(MemoryApiKeyStore::new()),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/integrity")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(body["chains"]["agents"], 2);
    assert_eq!(body["chains"]["receipts"], 3);
    assert_eq!(body["chains"]["unanchoredAgents"], 1);
    assert_eq!(body["chains"]["driftedAgents"], 0);
    assert_eq!(body["anchors"]["count"], 1);
    assert_eq!(body["anchors"]["pending"], 0);
    assert_eq!(body["keyEvents"]["count"], 1);
    assert_eq!(body["keyEvents"]["verified"], true);
    assert!(body["keys"]["active"].is_number());
    assert!(body["generatedAt"].is_string());
}

#[tokio::test]
async fn tenant_export_binds_the_ledger_and_checkpoints() {
    let svc = service(true).await;
    let mut req = request(10);
    req.agent_id = "archive-agent".into();
    svc.authorize("acme", req).await.unwrap();
    svc.append_key_event(
        "acme",
        "key.created",
        &{
            let mut record = tessera_broker::auth::new_record("acme", "ci", "tsk_x");
            record.id = "key_1".into();
            record
        },
        serde_json::json!({}),
    )
    .await
    .unwrap();

    // Archives write checkpoints; exports then carry ledger + checkpoints.
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("tessera-bind-{}-{}", std::process::id(), {
                unique_suffix()
            }));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir = Dir::new();
    svc.write_tenant_archive("acme", &dir.0)
        .await
        .unwrap()
        .unwrap();

    let bundle = svc.export_tenant("acme").await.unwrap();
    assert_eq!(bundle.key_events.len(), 1);
    assert_eq!(bundle.checkpoints.len(), 1);
    assert_eq!(bundle.policies.len(), 1);
    assert!(bundle.manifest.key_events_digest.is_some());
    assert!(bundle.manifest.checkpoints_digest.is_some());
    assert!(bundle.manifest.policies_digest.is_some());
    assert!(
        bundle.verify().unwrap(),
        "digests must be covered by the signature"
    );

    // Tampering with the ledger breaks verification (linkage + digest).
    let mut tampered = bundle.clone();
    tampered.key_events[0].details = serde_json::json!({ "tampered": true });
    assert!(!tampered.verify().unwrap());

    let mut tampered = bundle.clone();
    tampered.checkpoints[0].count = 999;
    assert!(!tampered.verify().unwrap());

    let mut tampered = bundle.clone();
    tampered.policies[0].document["name"] = serde_json::json!("tampered");
    assert!(!tampered.verify().unwrap());

    // The archive carries the new evidence files.
    let bytes = tessera_broker::export::build_tenant_archive(&bundle, "tessera-verify --archive .")
        .unwrap();
    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    let mut names = Vec::new();
    for entry in archive.entries().unwrap() {
        names.push(entry.unwrap().path().unwrap().to_string_lossy().to_string());
    }
    assert!(names.contains(&"key-events.json".to_string()));
    assert!(names.contains(&"checkpoints.json".to_string()));
    assert!(names.contains(&"policies.json".to_string()));
    assert!(names.contains(&"controls.json".to_string()));
}

#[tokio::test]
async fn drift_rearchives_and_signed_snapshots_bind_the_posture() {
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("tessera-snap-{}-{}", std::process::id(), {
                unique_suffix()
            }));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir = Dir::new();
    let mut base = (*service(true).await).clone();
    base.archive_dir = Some(dir.0.to_string_lossy().to_string());
    let svc = Arc::new(base);

    for amount in [10, 20, 30] {
        svc.authorize("acme", request(amount)).await.unwrap();
    }
    svc.write_tenant_archive("acme", &dir.0)
        .await
        .unwrap()
        .unwrap();

    // Signed integrity snapshot of the same posture.
    let report = svc.integrity_report("acme").await.unwrap();
    let (path, snapshot) = svc
        .write_signed_snapshot(&dir.0, "integrity", "acme", report.clone())
        .await
        .unwrap();
    assert!(path.exists());
    assert!(tessera_broker::export::verify_signed_payload(
        tessera_broker::export::INTEGRITY_DOMAIN,
        &report,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());
    // A changed value invalidates the snapshot.
    let mut tampered = report.clone();
    tampered["chains"]["receipts"] = serde_json::json!(999);
    assert!(!tessera_broker::export::verify_signed_payload(
        tessera_broker::export::INTEGRITY_DOMAIN,
        &tampered,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());

    // Both artifacts are indexed (archives and snapshots), and the index verifies.
    let index =
        std::fs::read_to_string(dir.0.join(tessera_broker::export::ARCHIVE_INDEX_FILE)).unwrap();
    let lines: Vec<serde_json::Value> = index
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    let kinds: Vec<String> = lines
        .iter()
        .map(|line| line["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"archive".to_string()));
    assert!(kinds.contains(&"integrity".to_string()));

    // Drift: rewrite history -> the re-archive path records a fresh checkpoint.
    let mut rewritten = (*svc).clone();
    let store: Arc<dyn tessera_broker::chain::ChainStore> =
        Arc::new(tessera_broker::chain::MemoryChainStore::new());
    rewritten.chain = store.clone();
    let other = service(true).await;
    for amount in [123, 124, 125] {
        other.authorize("acme", request(amount)).await.unwrap();
    }
    let foreign = other.export_chain("acme", "billing-agent").await.unwrap();
    for entry in &foreign.receipts {
        store
            .append("acme", "billing-agent", entry.clone())
            .await
            .unwrap();
    }
    let rewritten = Arc::new(rewritten);
    assert_eq!(rewritten.chain_drift("acme").await.unwrap().len(), 1);

    // Re-archiving after drift records reality; the drift is cleared and the old archive
    // (with the pre-drift checkpoint) is still on disk as evidence.
    let rearchived = rewritten
        .write_tenant_archive("acme", &dir.0)
        .await
        .unwrap()
        .unwrap();
    assert!(rearchived.exists());
    assert!(rewritten.chain_drift("acme").await.unwrap().is_empty());
    let archives = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("tessera-export-"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        archives, 2,
        "both the original and post-drift archives remain"
    );
}

#[tokio::test]
async fn http_integrity_snapshot_verifies() {
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    let app = app_of(svc.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/integrity?sign=true")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut document: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let snapshot: tessera_broker::export::SignedPayload = serde_json::from_value(
        document
            .as_object_mut()
            .unwrap()
            .remove("snapshot")
            .expect("snapshot present"),
    )
    .unwrap();
    assert!(tessera_broker::export::verify_signed_payload(
        tessera_broker::export::INTEGRITY_DOMAIN,
        &document,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());
}

#[tokio::test]
async fn snapshot_diffs_flag_unexpected_posture_changes() {
    let previous = serde_json::json!({
        "chains": { "agents": 2, "receipts": 10, "unanchoredAgents": 0, "driftedAgents": 0 },
        "anchors": { "count": 2 },
        "keyEvents": { "count": 5, "verified": true },
        "checkpoints": [{"agent": "a"}, {"agent": "b"}],
    });
    let current = serde_json::json!({
        "chains": { "agents": 2, "receipts": 9, "unanchoredAgents": 1, "driftedAgents": 1 },
        "anchors": { "count": 2 },
        "keyEvents": { "count": 5, "verified": false },
        "checkpoints": [{"agent": "a"}, {"agent": "b"}],
    });
    let changes = tessera_broker::authorize::AuthorizeService::diff_snapshots(&previous, &current);
    let by_field: std::collections::HashMap<_, _> = changes
        .iter()
        .map(|change| {
            (
                change["field"].as_str().unwrap().to_string(),
                change.clone(),
            )
        })
        .collect();

    // Rewind of receipts, new unanchored/drifted agents, and a broken ledger are unexpected.
    assert_eq!(by_field["chains.receipts"]["unexpected"], true);
    assert_eq!(by_field["chains.unanchoredAgents"]["unexpected"], true);
    assert_eq!(by_field["chains.driftedAgents"]["unexpected"], true);
    assert_eq!(by_field["keyEvents.verified"]["unexpected"], true);
    // Growth is recorded but not flagged.
    let grown = serde_json::json!({
        "chains": { "agents": 3, "receipts": 20, "unanchoredAgents": 0, "driftedAgents": 0 },
        "anchors": { "count": 4 },
        "keyEvents": { "count": 9, "verified": true },
        "checkpoints": [{"agent": "a"}, {"agent": "b"}, {"agent": "c"}],
    });
    let changes = tessera_broker::authorize::AuthorizeService::diff_snapshots(&previous, &grown);
    assert!(changes.iter().all(|change| change["unexpected"] != true));
    assert!(changes
        .iter()
        .any(|change| change["field"] == "chains.receipts"));
    // Identical payloads produce no changes at all.
    assert!(
        tessera_broker::authorize::AuthorizeService::diff_snapshots(&previous, &previous)
            .is_empty()
    );
}

#[tokio::test]
async fn snapshot_chain_on_disk_diffs_against_the_previous_file() {
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("tessera-diff-{}-{}", std::process::id(), {
                unique_suffix()
            }));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir = Dir::new();
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();

    let first = svc.integrity_report("acme").await.unwrap();
    svc.write_signed_snapshot(&dir.0, "integrity", "acme", first)
        .await
        .unwrap();

    let previous = tessera_broker::authorize::AuthorizeService::previous_snapshot(&dir.0, "acme")
        .expect("previous snapshot found");
    assert_eq!(previous["chains"]["receipts"], 1);

    // The chain grows: the next snapshot records the change, flagged as expected.
    svc.authorize("acme", request(20)).await.unwrap();
    let second = svc.integrity_report("acme").await.unwrap();
    let changes = tessera_broker::authorize::AuthorizeService::diff_snapshots(&previous, &second);
    assert!(changes
        .iter()
        .any(|change| change["field"] == "chains.receipts" && change["to"] == 2));
    assert!(changes.iter().all(|change| change["unexpected"] != true));
}

#[tokio::test]
async fn evidence_retention_prunes_old_files_and_records_it_in_the_index() {
    use std::fs;

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("tessera-prune-{}-{}", std::process::id(), {
                unique_suffix()
            }));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let dir = Dir::new();
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();

    // Two old archives and two old snapshots, plus a fresh snapshot.
    for timestamp in ["20200101T000000Z", "20200102T000000Z"] {
        fs::write(
            dir.0
                .join(format!("tessera-export-acme-{timestamp}-aaaaaaaa.tar.gz")),
            b"old archive",
        )
        .unwrap();
        fs::write(
            dir.0
                .join(format!("integrity-acme-{timestamp}-bbbbbbbb.json")),
            b"{}",
        )
        .unwrap();
    }
    let fresh = fs::read_dir(&dir.0).unwrap().count();
    let report = svc.integrity_report("acme").await.unwrap();
    let (fresh_path, _) = svc
        .write_signed_snapshot(&dir.0, "integrity", "acme", report)
        .await
        .unwrap();
    assert!(fresh_path.exists());

    let pruned = svc.prune_evidence(&dir.0, 30).await.unwrap();
    assert_eq!(pruned, 4, "two archives and both superseded snapshots");

    // The newest snapshot survives regardless of age; the index records the pruning.
    assert!(fresh_path.exists());
    assert!(!dir
        .0
        .join("tessera-export-acme-20200102T000000Z-aaaaaaaa.tar.gz")
        .exists());
    assert!(!dir
        .0
        .join("integrity-acme-20200101T000000Z-bbbbbbbb.json")
        .exists());
    let index = fs::read_to_string(dir.0.join(tessera_broker::export::ARCHIVE_INDEX_FILE)).unwrap();
    let entries: Vec<serde_json::Value> = index
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let pruned_entry = entries
        .iter()
        .find(|entry| entry["kind"] == "retention.pruned")
        .expect("pruning recorded in the index");
    assert_eq!(pruned_entry["files"].as_array().unwrap().len(), 4);
    // The retention entry is signed like every other index line.
    let mut entry = pruned_entry.clone();
    let snapshot: tessera_broker::export::SignedPayload = serde_json::from_value(
        entry
            .as_object_mut()
            .unwrap()
            .remove("snapshot")
            .expect("snapshot present"),
    )
    .unwrap();
    assert!(tessera_broker::export::verify_signed_payload(
        tessera_broker::export::ARCHIVE_INDEX_DOMAIN,
        &entry,
        &snapshot,
        &svc.accepted_signers(),
    )
    .unwrap());

    // Retention disabled keeps everything.
    assert_eq!(svc.prune_evidence(&dir.0, 0).await.unwrap(), 0);
    let _ = fresh;
}

#[tokio::test]
async fn import_is_linked_into_the_tenant_ledger() {
    let source = service(true).await;
    source.authorize("acme", request(10)).await.unwrap();
    let bundle = source.export_chain("acme", "billing-agent").await.unwrap();

    let target = service(true).await;
    let result = target.import_chain("acme", &bundle).await.unwrap();
    let attestation_digest = result["attestation"]["snapshot"]["digest"]
        .as_str()
        .unwrap()
        .to_string();

    let log = target.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["count"], 1);
    assert_eq!(log["verified"], true);
    assert_eq!(log["items"][0]["kind"], "chain.imported");
    assert_eq!(log["items"][0]["details"]["agent"], "billing-agent");
    assert_eq!(log["items"][0]["details"]["imported"], 1);
    assert_eq!(
        log["items"][0]["details"]["attestationDigest"], attestation_digest,
        "the ledger links the signed certificate"
    );

    // A later key event continues the same hash-linked history.
    let record = {
        let mut record = tessera_broker::auth::new_record("acme", "ci", "tsk_x");
        record.id = "key_1".into();
        record
    };
    target
        .append_key_event("acme", "key.created", &record, serde_json::json!({}))
        .await
        .unwrap();
    let log = target.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["count"], 2);
    assert_eq!(log["verified"], true);
    assert_eq!(
        log["items"][1]["prevHash"], log["items"][0]["eventHash"],
        "imports and key events share one chain"
    );
}

#[tokio::test]
async fn agent_scoped_keys_cannot_read_other_agents() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope};
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    for agent in ["billing-agent", "other-agent"] {
        let mut req = request(100);
        req.agent_id = agent.into();
        svc.authorize("acme", req).await.unwrap();
    }
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (_scoped, scoped_key) = keys
        .create(
            "acme",
            "billing-only",
            None,
            tessera_broker::auth::NewKeyOptions {
                scope: KeyScope {
                    resources: vec![],
                    agents: vec!["billing-agent".into()],
                    capabilities: vec![],
                    proxy_paths: vec![],
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys,
        demo_allow: false,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let get = |uri: &str| {
        let app = app.clone();
        let key = scoped_key.clone();
        let uri = uri.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .uri(uri)
                    .header("x-api-key", key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    assert_eq!(get("/v1/chain/billing-agent").await, StatusCode::OK);
    assert_eq!(get("/v1/chain/other-agent").await, StatusCode::FORBIDDEN);
    assert_eq!(
        get("/v1/chain/other-agent/anchor").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get("/v1/export/chain/other-agent").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get("/v1/chain/other-agent/proof?index=0").await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn authorize_is_idempotent_with_an_idempotency_key() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    let call = |idempotency: Option<&'static str>| {
        let app = app.clone();
        async move {
            let mut builder = Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme");
            if let Some(key) = idempotency {
                builder = builder.header("idempotency-key", key);
            }
            let response = app
                .oneshot(
                    builder
                        .body(Body::from(
                            serde_json::json!({
                                "agentId": "billing-agent",
                                "userId": "u1",
                                "tool": "stripe.refunds.create",
                                "intent": "refund",
                                "args": {"charge": "ch_1", "amount": 100}
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // Same key twice: same response, one chain entry.
    let (status1, first) = call(Some("retry-1")).await;
    let (status2, second) = call(Some("retry-1")).await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(first["receiptId"], second["receiptId"]);
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 1);

    // A different idempotency key issues a new credential and receipt.
    let (_, third) = call(Some("retry-2")).await;
    assert_ne!(third["receiptId"], first["receiptId"]);
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 2);

    // No header: no deduplication (existing behaviour).
    let (_, fourth) = call(None).await;
    assert_ne!(fourth["receiptId"], first["receiptId"]);
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 3);
}

#[tokio::test]
async fn import_accepts_bodies_larger_than_the_default_limit() {
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    let bundle = svc.export_chain("acme", "billing-agent").await.unwrap();

    // Pad the bundle with an ignored field so it exceeds the 64 KiB default body limit.
    let mut value = serde_json::to_value(&bundle).unwrap();
    value.as_object_mut().unwrap().insert(
        "padding".into(),
        serde_json::Value::String("x".repeat(200 * 1024)),
    );
    let body = serde_json::to_string(&value).unwrap();
    assert!(body.len() > 64 * 1024);

    let app = app_of(svc);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/import?dryRun=true")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the import route must accept bundles larger than 64 KiB"
    );
}

#[tokio::test]
async fn capabilities_restrict_what_a_key_can_do() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope};
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let scoped = |capabilities: Vec<&str>| KeyScope {
        resources: vec![],
        agents: vec![],
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        proxy_paths: vec![],
    };
    let (_proxy_only, proxy_only_key) = keys
        .create(
            "acme",
            "proxy-only",
            None,
            tessera_broker::auth::NewKeyOptions {
                scope: scoped(vec!["proxy"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_read_only, read_only_key) = keys
        .create(
            "acme",
            "read-only",
            None,
            tessera_broker::auth::NewKeyOptions {
                scope: scoped(vec!["read"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_full, full_key) = keys
        .create("acme", "full", None, Default::default())
        .await
        .unwrap();

    // Seed a chain so reads and records have something to act on.
    let allowed = svc.authorize("acme", request(100)).await.unwrap();
    let receipt_id = allowed.receipt_id.clone();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: false,
        admin_token: Some("admin-test".into()),
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let post = |key: &str, uri: &str, body: serde_json::Value| {
        let app = app.clone();
        let key = key.to_string();
        let uri = uri.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("x-api-key", key)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };
    let get = |key: &str, uri: &str| {
        let app = app.clone();
        let key = key.to_string();
        let uri = uri.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .uri(uri)
                    .header("x-api-key", key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    let authorize_body = serde_json::json!({
        "agentId": "billing-agent",
        "userId": "u1",
        "tool": "stripe.refunds.create",
        "intent": "refund",
        "args": {"charge": "ch_1", "amount": 100}
    });

    // proxy-only: cannot authorize, cannot read; the read of its own scope still works
    // through /v1/limits (which reports capabilities rather than requiring one).
    assert_eq!(
        post(&proxy_only_key, "/v1/authorize", authorize_body.clone()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(&proxy_only_key, "/v1/chain/billing-agent").await,
        StatusCode::FORBIDDEN
    );

    // read-only: can read, cannot authorize or record.
    assert_eq!(
        get(&read_only_key, "/v1/chain/billing-agent").await,
        StatusCode::OK
    );
    assert_eq!(
        post(&read_only_key, "/v1/authorize", authorize_body.clone()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            &read_only_key,
            "/v1/record",
            serde_json::json!({
                "agentId": "billing-agent",
                "receiptId": receipt_id,
                "resultHash": rh(0xdd),
                "status": "ok"
            })
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // Unscoped keys keep full access.
    assert_eq!(
        post(&full_key, "/v1/authorize", authorize_body).await,
        StatusCode::OK
    );

    // Capabilities are reported by the posture endpoint.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/limits")
                .header("x-api-key", read_only_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["keyScope"]["capabilities"][0], "read");
    assert_eq!(body["effectiveCapabilities"][0], "read");

    // Unknown capabilities are rejected at creation time.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-api-key", full_key.clone())
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({"name": "bad", "allowedCapabilities": ["admin"]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn record_and_proxy_replay_with_an_idempotency_key() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Mock upstream that counts requests.
    let hits = Arc::new(AtomicUsize::new(0));
    let handler_hits = hits.clone();
    let app = axum::Router::new().route(
        "/v1/refunds",
        axum::routing::post(move || {
            let hits = handler_hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({ "id": "re_1", "status": "succeeded" }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Stripe-style service with a mock base URL.
    use tessera_broker::issuers::stripe::StripeIssuer;
    use tessera_broker::issuers::IssuerRegistry;
    use tessera_broker::policy::{Constraint, InMemoryPolicyStore, Policy, ResourceGrant};
    let signer = Arc::new(
        tessera_broker::receipt::ReceiptSigner::from_hex_or_random(
            Some("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
            84532,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap(),
    );
    let mut keys_map = std::collections::HashMap::new();
    keys_map.insert("refunds_create".to_string(), "rk_test".to_string());
    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(StripeIssuer::new(
        tessera_broker::config::StripeConfig {
            restricted_keys: keys_map,
            api_base: format!("http://{addr}"),
        },
    )));
    let svc = Arc::new(tessera_broker::authorize::AuthorizeService {
        policies: Arc::new(InMemoryPolicyStore::new()),
        issuers: Arc::new(issuers),
        authority_hmac_secret: None,
        authority_require_token: false,
        signer,
        chain: Arc::new(tessera_broker::chain::MemoryChainStore::new()),
        telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        anchor: None,
        anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: Arc::new(tessera_broker::anchoring::MemoryAnchorTargetStore::new()),
        secrets: None,
        rpc_policy: Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min: None,
        tool_rate_limits: Vec::new(),
        max_ttl_seconds: 3600,
        signing_key_history: Vec::new(),
        anchor_gap_threshold: 0,
        ledger_retention_days: 0,
        archive_dir: None,
        archive_interval_secs: 3600,
        archive_replica_dir: None,
        archive_retention_days: 0,
        alert_router: Arc::new(tessera_broker::alerts::AlertRouter::new(
            Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
            None,
            None,
        )),
        alert_acks: Arc::new(tessera_broker::alert_acks::MemoryAlertAcks::new()),
        key_events: Arc::new(tessera_broker::key_events::MemoryKeyEvents::new()),
        chain_checkpoints: Arc::new(
            tessera_broker::chain_checkpoints::MemoryChainCheckpoints::new(),
        ),
        quota: Arc::new(tessera_broker::quota::QuotaManager::disabled()),
        remediation_policies: Arc::new(
            tessera_broker::remediation::MemoryRemediationPolicies::new(),
        ),
        tool_pins: Arc::new(tessera_broker::tool_pins::MemoryToolPins::new()),
        alert_webhook_url: None,
        alert_webhook_token: None,
        alert_repeat_secs: 3600,
        alert_retry_secs: 60,
        gap_alerts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        key_expiry_alert_days: 0,
        key_rotation_max_age_hours: None,
        retention_days: 0,
        anchor_confirmations: 0,
        anchor_reorg_grace_secs: 0,
        revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http: reqwest::Client::new(),
        default_ttl_seconds: 30,
        demo_policy: Some(Policy {
            id: "demo".into(),
            version: 1,
            name: "demo".into(),
            grants: vec![ResourceGrant {
                resource: "*".into(),
                constraints: vec![Constraint::MaxNumber {
                    field: "amount".into(),
                    value: 1e9,
                }],
                condition: None,
            }],
            fail_open: false,
            limits: Default::default(),
        }),
    });
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: Arc::new(tessera_broker::MemoryApiKeyStore::new()),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let post = |headers: Vec<(&str, &str)>, uri: &str, body: serde_json::Value| {
        let app = app.clone();
        let uri = uri.to_string();
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        async move {
            let mut builder = Request::builder().method("POST").uri(uri);
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
            let response = app
                .oneshot(
                    builder
                        .header("content-type", "application/json")
                        .header("x-tessera-tenant", "acme")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // Authorize a refund and proxy it twice with one idempotency key.
    let (_, allowed) = post(
        vec![],
        "/v1/authorize",
        serde_json::json!({
            "agentId": "billing-agent",
            "userId": "u1",
            "tool": "stripe.refunds.create",
            "intent": "refund",
            "args": {"charge": "ch_1", "amount": 100}
        }),
    )
    .await;
    let grant_id = allowed["credential"]["material"]["grantId"]
        .as_str()
        .expect("grant id")
        .to_string();
    let args_hash = allowed["credential"]["argsHash"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let proxy_body = serde_json::json!({
        "grantId": grant_id,
        "argsHash": args_hash,
        "method": "POST",
        "path": "/v1/refunds",
        "query": [],
        "body": null
    });
    let (status1, first) = post(
        vec![("idempotency-key", "proxy-1")],
        "/v1/proxy",
        proxy_body.clone(),
    )
    .await;
    let (status2, second) = post(
        vec![("idempotency-key", "proxy-1")],
        "/v1/proxy",
        proxy_body,
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(first, second, "the replay returns the original response");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the upstream was called once"
    );
    assert_eq!(first["outcomeRecorded"], true);
    assert_eq!(
        first["authorizationReceiptId"],
        allowed["receiptId"].clone()
    );
    assert_eq!(
        first["outcomeReceipt"]["outcome"]["source"],
        "broker_observed"
    );

    // The agent cannot overwrite the broker-observed outcome.
    let receipt_id = allowed["receiptId"].as_str().unwrap().to_string();
    let (conflict, body) = post(
        vec![("idempotency-key", "record-conflict")],
        "/v1/record",
        serde_json::json!({
            "agentId": "billing-agent",
            "receiptId": receipt_id,
            "resultHash": rh(0xdd),
            "status": "ok"
        }),
    )
    .await;
    assert_eq!(conflict, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("broker-held grants"), "{body}");
}

#[tokio::test]
async fn scope_updates_are_audited_and_enforced() {
    use tessera_broker::auth::ApiKeyStore;
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());

    // A bootstrap key to authenticate key management with.
    let (_bootstrap, bootstrap_key) = keys
        .create("acme", "bootstrap", None, Default::default())
        .await
        .unwrap();

    // Seed a chain so reads work.
    svc.authorize("acme", request(10)).await.unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys: keys.clone(),
        demo_allow: false,
        admin_token: Some("admin-test".into()),
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));
    // Create the key through the API so the ledger records the creation too.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-api-key", bootstrap_key.clone())
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({"name": "evolving"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let key = created["key"].as_str().unwrap().to_string();
    let record_id = created["record"]["id"].as_str().unwrap().to_string();

    let authorize_call = |key: String| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .header("x-api-key", key)
                    .body(Body::from(
                        serde_json::json!({
                            "agentId": "billing-agent",
                            "userId": "u1",
                            "tool": "stripe.refunds.create",
                            "intent": "refund",
                            "args": {"charge": "ch_1", "amount": 100}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    // The unscoped key can authorize.
    assert_eq!(authorize_call(key.clone()).await, StatusCode::OK);

    // Narrow it to read-only and change the budget in one call.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/keys/{record_id}"))
                .header("content-type", "application/json")
                .header("x-api-key", key.clone())
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({
                        "allowedCapabilities": ["read"],
                        "rateLimitPerMin": 5
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The update takes effect immediately (auth cache cleared).
    assert_eq!(
        authorize_call(key.clone()).await,
        StatusCode::FORBIDDEN,
        "the narrowed key must no longer authorize"
    );

    // Ledger records both changes with before/after details, and still verifies.
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["verified"], true);
    let kinds: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"key.created"));
    assert!(kinds.contains(&"key.scope-changed"));
    assert!(kinds.contains(&"key.budget-changed"));
    let scope_event = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "key.scope-changed")
        .unwrap();
    assert_eq!(scope_event["details"]["after"]["capabilities"][0], "read");
    assert_eq!(
        scope_event["details"]["before"]["capabilities"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Updating a missing key is a 404.
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/keys/key_missing")
                .header("content-type", "application/json")
                .header("x-api-key", key)
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({"allowedCapabilities": ["read"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn key_templates_resolve_to_scopes_and_reject_conflicts() {
    use tessera_broker::auth::{ApiKeyStore, MemoryApiKeyStore};

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let create = |body: serde_json::Value| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/keys")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // A template resolves to its canonical scope.
    let (status, body) = create(serde_json::json!({"name": "m", "template": "monitor"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["scope"]["capabilities"][0], "read");
    let (status, body) =
        create(serde_json::json!({"name": "p", "template": "payments-integration"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["scope"]["resources"][0], "stripe:*");
    assert_eq!(
        body["record"]["scope"]["capabilities"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // Template + explicit scope fields is ambiguous.
    let (status, _) = create(serde_json::json!({
        "name": "x",
        "template": "monitor",
        "allowedCapabilities": ["read"]
    }))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Unknown templates list the available ones.
    let (status, body) = create(serde_json::json!({"name": "y", "template": "root"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["allowed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "monitor"));

    // The catalogue is discoverable.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/key-templates")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let names: Vec<&str> = body["templates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|template| template["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"payments-integration"));

    // The template-created key really is read-only.
    let record = keys
        .authenticate(
            body["templates"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == "monitor")
                .map(|_| "")
                .unwrap_or(""),
        )
        .await
        .unwrap();
    assert!(record.is_none());
}

#[tokio::test]
async fn proxy_path_allowlist_blocks_other_upstream_paths() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let upstream = axum::Router::new().route(
        "/v1/refunds",
        axum::routing::post(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({ "ok": true }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });

    // Stripe-style service pointed at the mock upstream.
    use tessera_broker::issuers::stripe::StripeIssuer;
    use tessera_broker::issuers::IssuerRegistry;
    let mut keys_map = std::collections::HashMap::new();
    keys_map.insert("refunds_create".to_string(), "rk_test".to_string());
    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(StripeIssuer::new(
        tessera_broker::config::StripeConfig {
            restricted_keys: keys_map,
            api_base: format!("http://{addr}"),
        },
    )));
    let mut base = (*service(true).await).clone();
    base.issuers = Arc::new(issuers);
    let svc = Arc::new(base);

    let (grant_id, args_hash) = {
        let allowed = svc.authorize("acme", request(100)).await.unwrap();
        let credential = allowed.credential.unwrap();
        let args_hash = credential.args_hash.clone();
        let grant_id = match credential.material {
            tessera_broker::issuers::CredentialMaterial::Grant { grant_id, .. } => grant_id,
            other => panic!("expected grant material, got {other:?}"),
        };
        (grant_id, args_hash)
    };

    let scope = tessera_broker::auth::KeyScope {
        resources: vec![],
        agents: vec![],
        capabilities: vec![],
        proxy_paths: vec!["/v1/refunds*".into()],
    };

    // A path outside the allowlist is denied and the grant is not consumed.
    let err = svc
        .proxy_scoped(
            "acme",
            tessera_proxy_request(&grant_id, &args_hash, "/v1/charges"),
            Some(&scope),
        )
        .await
        .expect_err("path must be denied");
    assert!(matches!(err, tessera_broker::BrokerError::Denied(_)));
    assert_eq!(hits.load(Ordering::SeqCst), 0, "upstream untouched");

    // An allowed path goes through.
    if let Err(err) = svc
        .proxy_scoped(
            "acme",
            tessera_proxy_request(&grant_id, &args_hash, "/v1/refunds"),
            Some(&scope),
        )
        .await
    {
        panic!("allowed path failed: {err}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

fn tessera_proxy_request(
    grant_id: &str,
    args_hash: &str,
    path: &str,
) -> tessera_broker::proxy::ProxyRequest {
    tessera_broker::proxy::ProxyRequest {
        grant_id: grant_id.to_string(),
        args_hash: args_hash.to_string(),
        method: "POST".into(),
        path: path.into(),
        query: vec![],
        content_type: None,
        body: None,
    }
}

#[tokio::test]
async fn key_lint_reports_keys_broader_than_a_template() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope, NewKeyOptions};
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    // Unrestricted key (exceeds every template).
    keys.create("acme", "unrestricted", None, Default::default())
        .await
        .unwrap();
    // A monitor-shaped key (compliant with `monitor`).
    keys.create(
        "acme",
        "monitor",
        None,
        NewKeyOptions {
            scope: KeyScope {
                resources: vec![],
                agents: vec![],
                capabilities: vec!["read".into()],
                proxy_paths: vec![],
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // A stripe key that can also write (exceeds `monitor` on capabilities).
    keys.create(
        "acme",
        "stripe-writer",
        None,
        NewKeyOptions {
            scope: KeyScope {
                resources: vec!["stripe:*".into()],
                agents: vec![],
                capabilities: vec!["authorize".into(), "read".into()],
                proxy_paths: vec![],
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys,
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/keys/lint?template=monitor")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["compliantCount"], 1, "the monitor-shaped key is fine");
    assert_eq!(body["exceedingCount"], 2);
    let unresticted = body["exceeding"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "unrestricted")
        .unwrap();
    assert!(unresticted["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap().contains("every capability")));
    let writer = body["exceeding"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "stripe-writer")
        .unwrap();
    assert!(writer["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap().contains("'authorize'")));

    // Unknown templates list the alternatives.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/keys/lint?template=root")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn key_updates_honour_if_match() {
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"name": "etag-key"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created["record"]["id"].as_str().unwrap().to_string();
    let etag = tessera_broker::auth::key_etag(
        &serde_json::from_value::<tessera_broker::auth::ApiKeyRecord>(created["record"].clone())
            .unwrap(),
    );
    assert_eq!(etag, "\"v1\"");

    let patch = |if_match: Option<String>, capabilities: serde_json::Value| {
        let app = app.clone();
        let id = id.clone();
        async move {
            let mut builder = Request::builder()
                .method("PATCH")
                .uri(format!("/v1/keys/{id}"))
                .header("content-type", "application/json");
            if let Some(value) = if_match {
                builder = builder.header("if-match", value);
            }
            app.oneshot(
                builder
                    .body(Body::from(
                        serde_json::json!({"allowedCapabilities": capabilities}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    // Stale ETag -> 412.
    assert_eq!(
        patch(Some("\"v9\"".into()), serde_json::json!(["read"])).await,
        StatusCode::PRECONDITION_FAILED
    );
    // Malformed ETag -> 400.
    assert_eq!(
        patch(Some("not-a-version".into()), serde_json::json!(["read"])).await,
        StatusCode::BAD_REQUEST
    );
    // Correct ETag -> 200, and the version advances.
    assert_eq!(
        patch(Some(etag), serde_json::json!(["read"])).await,
        StatusCode::OK
    );
    use tessera_broker::auth::ApiKeyStore;
    let record = keys
        .list("default")
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.id == id)
        .unwrap();
    assert_eq!(record.version, 2);
    assert_eq!(tessera_broker::auth::key_etag(&record), "\"v2\"");
    // The same ETag is now stale.
    assert_eq!(
        patch(Some("\"v1\"".into()), serde_json::json!(["read"])).await,
        StatusCode::PRECONDITION_FAILED
    );
}

#[tokio::test]
async fn key_templates_carry_default_budgets() {
    let svc = service(true).await;
    let app = app_of(svc);

    // The catalogue advertises the default budget.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/key-templates")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let monitor = body["templates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|template| template["name"] == "monitor")
        .unwrap();
    assert_eq!(monitor["defaultRateLimitPerMin"], 60);

    let create = |body: serde_json::Value| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/keys")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap()
        }
    };

    // A template key without an explicit budget gets the preset's default.
    let created = create(serde_json::json!({"name": "templated", "template": "monitor"})).await;
    assert_eq!(created["record"]["rateLimitPerMin"], 60);
    // An explicit budget wins.
    let created = create(serde_json::json!({
        "name": "explicit",
        "template": "monitor",
        "rateLimitPerMin": 5
    }))
    .await;
    assert_eq!(created["record"]["rateLimitPerMin"], 5);
}

#[tokio::test]
async fn renew_and_revoke_honour_if_match() {
    use tessera_broker::auth::{ApiKeyStore, MutateOutcome};
    use tessera_broker::MemoryApiKeyStore;

    let keys = MemoryApiKeyStore::new();
    let (record, key) = keys
        .create("acme", "conditional", None, Default::default())
        .await
        .unwrap();
    assert_eq!(record.version, 1);

    // A stale precondition fails without rotating the secret.
    let outcome = keys.renew("acme", &record.id, None, Some(9)).await.unwrap();
    assert_eq!(outcome, MutateOutcome::Conflict { current: 1 });
    assert!(keys.authenticate(&key).await.unwrap().is_some());

    // The current version rotates and advances the revision.
    let outcome = keys.renew("acme", &record.id, None, Some(1)).await.unwrap();
    let (renewed, new_key) = match outcome {
        MutateOutcome::Done(result) => result,
        other => panic!("expected rotation, got {other:?}"),
    };
    assert_eq!(renewed.version, 2);
    assert!(keys.authenticate(&key).await.unwrap().is_none());
    assert!(keys.authenticate(&new_key).await.unwrap().is_some());

    // Revocation is conditional too.
    assert_eq!(
        keys.revoke("acme", &record.id, Some(1)).await.unwrap(),
        MutateOutcome::Conflict { current: 2 }
    );
    assert_eq!(
        keys.revoke("acme", &record.id, Some(2)).await.unwrap(),
        MutateOutcome::Done(())
    );
    assert_eq!(
        keys.revoke("acme", &record.id, None).await.unwrap(),
        MutateOutcome::NotFound
    );
}

#[tokio::test]
async fn lint_remediation_narrows_over_granted_keys() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    // Two over-granted keys and one compliant monitor key.
    for name in ["loose-a", "loose-b"] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keys")
                    .header("content-type", "application/json")
                    .header("x-tessera-tenant", "acme")
                    .body(Body::from(serde_json::json!({"name": name}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"name": "strict", "template": "monitor"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // A dry run reports without changing anything.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys/lint")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"template": "monitor", "apply": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["remediatedCount"], 0);
    assert_eq!(body["skippedCount"], 2);

    // Applying narrows both keys and records the change.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys/lint")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"template": "monitor", "apply": true}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["remediatedCount"], 2, "response: {body}");
    assert_eq!(body["compliant"], 1, "response: {body}");

    // The GET lint now reports no over-grants.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/keys/lint?template=monitor")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["exceedingCount"], 0);

    // The ledger holds the remediation with before/after detail and still verifies.
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["verified"], true);
    let remediation = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "key.scope-remediated")
        .expect("remediation recorded");
    assert_eq!(remediation["details"]["template"], "monitor");
    assert_eq!(
        remediation["details"]["before"]["capabilities"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(remediation["details"]["after"]["capabilities"][0], "read");
}

#[tokio::test]
async fn key_lifecycle_events_reach_the_tenant_webhook() {
    use std::sync::Mutex as StdMutex;

    use axum::extract::State;
    use tessera_broker::alerts::{
        AlertRouter, AlertTarget, AlertTargetStore, MemoryAlertTargetStore,
    };

    #[derive(Clone)]
    struct Sink(Arc<StdMutex<Vec<serde_json::Value>>>);

    async fn handler(
        State(sink): State<Sink>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        sink.0.lock().unwrap().push(body);
        StatusCode::OK
    }

    let sink = Sink(Arc::new(StdMutex::new(Vec::new())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = axum::Router::new()
        .route("/lifecycle", axum::routing::post(handler))
        .with_state(sink.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let store = Arc::new(MemoryAlertTargetStore::new());
    store
        .set(
            "acme",
            AlertTarget {
                url: format!("http://{addr}/lifecycle"),
                token: None,
                events: vec!["key.lifecycle".into()],
                auto_ack_below: None,
            },
        )
        .await
        .unwrap();

    let mut base = (*service(true).await).clone();
    base.alert_router = Arc::new(AlertRouter::new(store, None, None));
    let svc = Arc::new(base);
    let app = app_of(svc.clone());

    let post = |uri: String, body: serde_json::Value| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("x-tessera-tenant", "acme")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let created = post("/v1/keys".into(), serde_json::json!({"name": "hooked"})).await;
    let created_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = created_body["record"]["id"].as_str().unwrap().to_string();
    let _ = post(format!("/v1/keys/{id}/renew"), serde_json::json!({})).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/keys/{id}"))
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let delivered = sink.0.lock().unwrap().clone();
    let actions: Vec<String> = delivered
        .iter()
        .map(|event| event["action"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        actions,
        vec!["key.created", "key.renewed", "key.revoked"],
        "every lifecycle change is delivered, in order, with no suppression"
    );
    // Events are signed and carry identifying metadata.
    let first = &delivered[0];
    assert!(first["snapshot"]["signature"].is_string());
    assert_eq!(first["tenant"], "acme");
    assert_eq!(first["name"], "hooked");
}

#[tokio::test]
async fn auto_remediation_policy_narrows_new_and_widened_keys() {
    use tessera_broker::remediation::RemediationPolicy;
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    svc.remediation_policies
        .set(
            "acme",
            RemediationPolicy {
                template: "monitor".into(),
                template_version: Some(1),
                enabled: true,
                updated_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys: keys.clone(),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let post = |uri: String, body: serde_json::Value| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .header("x-tessera-tenant", "acme")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // An unrestricted key is narrowed on creation.
    let (status, created) = post("/v1/keys".into(), serde_json::json!({"name": "loose"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        created["record"]["scope"]["capabilities"][0], "read",
        "response already reports the narrowed scope"
    );
    assert_eq!(
        created["record"]["version"], 2,
        "the narrowing bumped the revision"
    );

    // A compliant key is untouched.
    let (_, strict) = post(
        "/v1/keys".into(),
        serde_json::json!({"name": "strict", "template": "monitor"}),
    )
    .await;
    assert_eq!(strict["record"]["version"], 1);

    // Widening a key via PATCH is also narrowed back.
    let id = strict["record"]["id"].as_str().unwrap().to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/keys/{id}"))
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"allowedCapabilities": ["authorize", "proxy"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["record"]["scope"]["capabilities"][0], "read");

    // The ledger records both automatic narrowings and still verifies.
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["verified"], true);
    let auto: Vec<&serde_json::Value> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["kind"] == "key.auto-remediated")
        .collect();
    assert_eq!(auto.len(), 2);
    assert_eq!(auto[0]["details"]["template"], "monitor");

    // Disabling the policy stops the narrowing.
    svc.remediation_policies
        .set(
            "acme",
            RemediationPolicy {
                template: "monitor".into(),
                template_version: Some(1),
                enabled: false,
                updated_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();
    let (_, loose_again) = post("/v1/keys".into(), serde_json::json!({"name": "loose-2"})).await;
    // Empty dimensions are omitted by the serializer: an unrestricted key has none.
    assert!(loose_again["record"]["scope"].get("capabilities").is_none());
    assert!(loose_again["record"]["scope"].get("resources").is_none());
}

#[tokio::test]
async fn lint_previews_the_exact_scope_diff() {
    let svc = service(true).await;
    let app = app_of(svc);

    // A key with extra resources, a missing capability, and no proxy allowlist.
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({
                        "name": "wide",
                        "allowedResources": ["stripe:*", "aws:*"],
                        "allowedCapabilities": ["authorize", "proxy"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys/lint")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"template": "monitor", "apply": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let preview = body["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "wide")
        .expect("wide key previewed");
    let diff = &preview["diff"];
    // Applying monitor removes the extra resources and capabilities, and adds `read`.
    let removed_caps: Vec<&str> = diff["capabilities"]["remove"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(removed_caps.contains(&"authorize"));
    assert!(removed_caps.contains(&"proxy"));
    assert_eq!(diff["capabilities"]["add"][0], "read");
    let removed_resources: Vec<&str> = diff["resources"]["remove"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(removed_resources.contains(&"aws:*"));
    assert!(removed_resources.contains(&"stripe:*"));
    // The preview did not change the key.
    assert_eq!(
        preview["before"]["capabilities"].as_array().unwrap().len(),
        2
    );
}

#[tokio::test]
async fn policy_preview_shows_what_enabling_would_narrow() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    // A loose key and a compliant one.
    for body in [
        serde_json::json!({"name": "loose"}),
        serde_json::json!({"name": "strict", "template": "monitor"}),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keys")
                    .header("content-type", "application/json")
                    .header("x-tessera-tenant", "acme")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/remediation-policy/preview")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"template": "monitor"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["wouldNarrowCount"], 1);
    assert_eq!(body["compliantCount"], 1);
    assert_eq!(body["wouldNarrow"][0]["name"], "loose");
    assert_eq!(
        body["wouldNarrow"][0]["diff"]["capabilities"]["add"][0],
        "read"
    );
    assert!(
        body["currentPolicy"].is_null(),
        "preview does not store a policy"
    );

    // The preview did not change the key.
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["count"], 2, "only the two creations");

    // Unknown templates list the alternatives.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/remediation-policy/preview")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"template": "root"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn key_event_log_replays_in_pages() {
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys,
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    // Three lifecycle events, with distinct timestamps.
    for name in ["a", "b", "c"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keys")
                    .header("content-type", "application/json")
                    .header("x-tessera-tenant", "acme")
                    .body(Body::from(serde_json::json!({"name": name}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }

    let get = |query: &str| {
        let app = app.clone();
        let uri = format!("/v1/key-events{query}");
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("x-tessera-tenant", "acme")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // Full ledger.
    let (_, full) = get("").await;
    assert_eq!(full["count"], 3);
    assert_eq!(full["returned"], 3);
    assert_eq!(full["hasMore"], false);
    assert_eq!(full["verified"], true);

    // Page of one.
    let (_, page) = get("?limit=1").await;
    assert_eq!(page["returned"], 1);
    assert_eq!(page["hasMore"], true);
    assert_eq!(page["items"][0]["keyName"], "a");
    assert_eq!(page["count"], 3, "the total is still reported");
    let next = page["nextSince"].as_str().unwrap().to_string();

    // Replay from the cursor: the remaining two events, and never the first again.
    let (_, replay) = get(&format!("?since={next}")).await;
    assert_eq!(replay["returned"], 2);
    assert_eq!(replay["items"][0]["keyName"], "b");
    assert_eq!(replay["items"][1]["keyName"], "c");
    assert_eq!(
        replay["verified"], true,
        "verification covers the full ledger"
    );

    // A bogus cursor is a 400; the space-decoded form of a `+00:00` cursor still parses.
    let (status, _) = get("?since=not-a-date").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn evidence_exports_page_deterministically() {
    let svc = service(true).await;
    for amount in [10, 20, 30, 40, 50] {
        svc.authorize("acme", request(amount)).await.unwrap();
    }
    let full = svc.chain.chain("acme", "billing-agent").await.unwrap();

    // Middle page: self-contained, linked to its predecessor.
    let page = svc
        .build_agent_export_page("acme", "billing-agent", Some(2), Some(2))
        .await
        .unwrap();
    assert_eq!(page.manifest.from_index, 2);
    assert_eq!(page.manifest.receipt_count, 2);
    assert_eq!(page.manifest.chain_length, 5);
    assert_eq!(
        page.manifest.prev_before.as_deref(),
        Some(full[1].payload_hash.as_str())
    );
    assert_eq!(page.manifest.next_from, Some(4));
    assert!(page.verify().unwrap(), "a page verifies on its own");

    // Final page: no continuation pointer.
    let last = svc
        .build_agent_export_page("acme", "billing-agent", Some(4), Some(2))
        .await
        .unwrap();
    assert_eq!(last.manifest.receipt_count, 1);
    assert_eq!(last.manifest.next_from, None);
    assert_eq!(
        last.manifest.prev_before.as_deref(),
        Some(full[3].payload_hash.as_str())
    );
    assert!(last.verify().unwrap());

    // The default window is the most recent page, still verifiable.
    let default_window = svc
        .build_agent_export_page("acme", "billing-agent", None, None)
        .await
        .unwrap();
    assert_eq!(default_window.manifest.from_index, 0);
    assert!(default_window.verify().unwrap());

    // Concatenating the pages reconstructs the chain in order.
    let mut rebuilt = Vec::new();
    let mut from = Some(0);
    while let Some(index) = from {
        let page = svc
            .build_agent_export_page("acme", "billing-agent", Some(index), Some(2))
            .await
            .unwrap();
        assert!(page.verify().unwrap());
        rebuilt.extend(page.receipts.iter().map(|entry| entry.payload_hash.clone()));
        from = page.manifest.next_from;
    }
    let expected: Vec<String> = full
        .iter()
        .map(|entry| entry.payload_hash.clone())
        .collect();
    assert_eq!(rebuilt, expected);

    // Tampering with the page linkage breaks verification.
    let mut tampered = svc
        .build_agent_export_page("acme", "billing-agent", Some(2), Some(2))
        .await
        .unwrap();
    tampered.manifest.prev_before = Some(full[0].payload_hash.clone());
    assert!(!tampered.verify().unwrap());
    // A page that hides its continuation pointer is invalid.
    let mut hidden = svc
        .build_agent_export_page("acme", "billing-agent", Some(0), Some(2))
        .await
        .unwrap();
    hidden.manifest.from_index = 1;
    assert!(!hidden.verify().unwrap());
}

#[tokio::test]
async fn webhook_deliveries_are_recorded_in_the_ledger() {
    use std::sync::Mutex as StdMutex;

    use axum::extract::State;
    use tessera_broker::alerts::{
        AlertRouter, AlertTarget, AlertTargetStore, MemoryAlertTargetStore,
    };

    #[derive(Clone)]
    struct Sink(Arc<StdMutex<Vec<serde_json::Value>>>);

    async fn handler(
        State(sink): State<Sink>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        sink.0.lock().unwrap().push(body);
        StatusCode::OK
    }

    let sink = Sink(Arc::new(StdMutex::new(Vec::new())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = axum::Router::new()
        .route("/hook", axum::routing::post(handler))
        .with_state(sink.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let store = Arc::new(MemoryAlertTargetStore::new());
    store
        .set(
            "acme",
            AlertTarget {
                url: format!("http://{addr}/hook"),
                token: None,
                events: vec![],
                auto_ack_below: None,
            },
        )
        .await
        .unwrap();

    let mut base = (*service(true).await).clone();
    base.alert_router = Arc::new(AlertRouter::new(store, None, None));
    let svc = Arc::new(base);
    let app = app_of(svc.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"name": "hooked"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["verified"], true);
    let kinds: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["key.created", "webhook.delivery"]);
    let receipt = &log["items"][1];
    assert_eq!(receipt["details"]["event"], "key.lifecycle");
    assert_eq!(receipt["details"]["action"], "key.created");
    assert_eq!(receipt["details"]["delivered"], true);
    assert_eq!(receipt["details"]["status"], 200);
    assert_eq!(sink.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn stale_remediation_policies_stop_acting() {
    use tessera_broker::remediation::RemediationPolicy;
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    // A policy pinned to an older template revision.
    svc.remediation_policies
        .set(
            "acme",
            RemediationPolicy {
                template: "monitor".into(),
                template_version: Some(0),
                enabled: true,
                updated_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys,
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    // A stale policy does not narrow anything.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(serde_json::json!({"name": "loose"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        body["record"]["scope"].get("capabilities").is_none(),
        "a stale policy must not act: {body}"
    );

    // Re-approving through the API pins the current revision and takes effect.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/remediation-policy")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"template": "monitor"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let policy: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(policy["policy"]["templateVersion"], 1);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"name": "loose-2"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["record"]["scope"]["capabilities"][0], "read");
}

#[tokio::test]
async fn idempotency_keys_are_bound_to_the_request() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    let post = |idempotency: &'static str, amount: i64| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/authorize")
                        .header("content-type", "application/json")
                        .header("idempotency-key", idempotency)
                        .header("x-tessera-tenant", "acme")
                        .body(Body::from(
                            serde_json::json!({
                                "agentId": "billing-agent",
                                "userId": "u1",
                                "tool": "stripe.refunds.create",
                                "intent": "refund",
                                "args": {"charge": "ch_1", "amount": amount}
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // Same key, same request: replay.
    let (status, first) = post("bound-1", 100).await;
    assert_eq!(status, StatusCode::OK);
    let (status, replay) = post("bound-1", 100).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["receiptId"], first["receiptId"]);

    // Same key, different request: rejected instead of replaying an unrelated response.
    let (status, body) = post("bound-1", 200).await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("different request"));
    // ...and the rejected attempt did not create a receipt.
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 1);

    // A fresh key for the different amount succeeds normally.
    let (status, other) = post("bound-2", 200).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(other["receiptId"], first["receiptId"]);
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 2);
}

#[tokio::test]
async fn anchor_config_check_reports_rpc_and_contract_state() {
    use tessera_broker::anchoring::AnchorTarget;
    use tessera_broker::netguard::RpcPolicy;

    // A strict policy rejects private targets, so a loopback probe is refused up front.
    let mut base = (*service(true).await).clone();
    base.rpc_policy = Arc::new(RpcPolicy::new(false, vec![]));
    base.secrets = Some(Arc::new(
        tessera_broker::secrets::Envelope::from_hex(&"44".repeat(32)).unwrap(),
    ));
    let svc = Arc::new(base);
    svc.set_anchor_target(
        "acme",
        AnchorTarget {
            chain_id: 31337,
            rpc_url: "https://rpc.example.invalid".into(),
            contract: "0x0000000000000000000000000000000000000001".into(),
            // A tenant key lets the check build a submitter without the global anchor config.
            private_key: Some(
                "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
            ),
            signer_history: vec![],
        },
    )
    .await
    .unwrap();

    // Public but unreachable: reported as not reachable, without panicking.
    let report = svc.check_anchor_target("acme").await.unwrap();
    assert_eq!(report["rpcReachable"], false);
    assert!(report["contract"].as_str().unwrap().starts_with("0x"));
    assert!(report["error"].is_string());

    // Without a tenant target or a global anchor, the check refuses clearly.
    assert!(matches!(
        svc.check_anchor_target("other").await.unwrap_err(),
        tessera_broker::BrokerError::NotConfigured(_)
    ));
}

#[tokio::test]
async fn ledger_compaction_keeps_the_chain_verifiable() {
    use tessera_broker::key_events::{KeyEventStore, MemoryKeyEvents};

    let store = MemoryKeyEvents::new();
    let mut previous: Option<String> = None;
    for (index, kind) in ["key.created", "key.renewed", "key.revoked"]
        .iter()
        .enumerate()
    {
        let mut event = tessera_broker::key_events::KeyEvent {
            id: format!("kev_{index}"),
            tenant: "acme".into(),
            kind: kind.to_string(),
            key_id: "key_1".into(),
            key_name: "ci".into(),
            prefix: "tsk_x".into(),
            details: serde_json::json!({}),
            at: format!("2020-01-0{}T00:00:00Z", index + 1),
            prev_hash: previous.clone(),
            event_hash: String::new(),
            signature: None,
        };
        event.event_hash = format!(
            "0x{}",
            hex::encode(tessera_broker::key_events::event_digest(&event).unwrap())
        );
        previous = Some(event.event_hash.clone());
        store.append(event).await.unwrap();
    }

    // Compact everything older than 2020-01-03: the first two events go.
    let cutoff = chrono::DateTime::parse_from_rfc3339("2020-01-03T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let checkpoint = tessera_broker::key_events::KeyEvent {
        id: "kev_compact".into(),
        tenant: "acme".into(),
        kind: "ledger.compacted".into(),
        key_id: String::new(),
        key_name: String::new(),
        prefix: String::new(),
        details: serde_json::json!({ "retentionDays": 1 }),
        at: "2026-09-17T00:00:00Z".into(),
        prev_hash: None,
        event_hash: String::new(),
        signature: None,
    };
    let (removed, _checkpoint) = store
        .compact("acme", cutoff, checkpoint)
        .await
        .unwrap()
        .expect("compaction happened");
    assert_eq!(removed, 2);

    let events = store.list("acme").await.unwrap();
    let kinds: Vec<&str> = events.iter().map(|event| event.kind.as_str()).collect();
    assert_eq!(kinds, vec!["key.revoked", "ledger.compacted"]);

    // The remaining ledger still verifies: the checkpoint anchors the pruned prefix.
    assert!(tessera_broker::key_events::verify_chain(&events));

    // Tampering with the checkpoint's claim about the pruned hash is detectable.
    let mut tampered = events.clone();
    tampered[1].prev_hash = Some("0xdead".into());
    assert!(!tessera_broker::key_events::verify_chain(&tampered));

    // Idempotent when there is nothing left to prune.
    let checkpoint = tessera_broker::key_events::KeyEvent {
        id: "kev_compact_2".into(),
        tenant: "acme".into(),
        kind: "ledger.compacted".into(),
        key_id: String::new(),
        key_name: String::new(),
        prefix: String::new(),
        details: serde_json::json!({}),
        at: "2026-09-17T00:00:00Z".into(),
        prev_hash: None,
        event_hash: String::new(),
        signature: None,
    };
    assert!(store
        .compact("acme", cutoff, checkpoint)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn tenant_settings_require_admin_authorization() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope, NewKeyOptions};
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    let keys = Arc::new(MemoryApiKeyStore::new());
    // A read-capable (and even write-capable) integration key: still not an admin.
    let (_reader, reader_key) = keys
        .create(
            "acme",
            "reader",
            None,
            NewKeyOptions {
                scope: KeyScope {
                    capabilities: vec!["read".into(), "authorize".into(), "proxy".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_bootstrap, bootstrap_key) = keys
        .create("acme", "bootstrap", None, Default::default())
        .await
        .unwrap();

    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: keys.clone(),
        demo_allow: false,
        admin_token: Some("admin-test".into()),
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    // Write and admin-only routes refuse a non-admin key, whatever its capabilities.
    // (The read routes allow a *redacted* summary for read-capable keys, asserted below.)
    let settings_routes: Vec<(&str, serde_json::Value)> = vec![
        (
            "PUT /v1/anchor-config",
            serde_json::json!({
                "chainId": 31337,
                "rpcUrl": "https://rpc.example.com",
                "contract": "0x0000000000000000000000000000000000000001",
                "privateKey": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
            }),
        ),
        ("POST /v1/anchor-config/check", serde_json::Value::Null),
        (
            "PUT /v1/alert-config",
            serde_json::json!({"url": "https://hooks.attacker.example/x"}),
        ),
        ("DELETE /v1/alert-config", serde_json::Value::Null),
        (
            "PUT /v1/remediation-policy",
            serde_json::json!({"template": "monitor"}),
        ),
        ("DELETE /v1/remediation-policy", serde_json::Value::Null),
    ];

    for (route, body) in settings_routes {
        let mut parts = route.split(' ');
        let method = parts.next().unwrap();
        let uri = parts.next().unwrap();
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-api-key", reader_key.clone())
            .body(if body.is_null() {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{route} must require an admin, got {status}"
        );
    }

    // Read routes answer read-capable keys with a redacted summary instead of 403.
    for uri in [
        "/v1/anchor-config",
        "/v1/alert-config",
        "/v1/remediation-policy",
    ] {
        let status = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("x-api-key", reader_key.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(
            status,
            StatusCode::OK,
            "{uri} should be readable (redacted)"
        );
    }

    // A key without any capability is refused on the same reads.
    let (_nobody, nobody_key) = keys
        .create("acme", "nobody", None, Default::default())
        .await
        .unwrap();
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/anchor-config")
                .header("x-api-key", nobody_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        StatusCode::OK,
        "an unrestricted key is not capability-limited"
    );

    // With the admin token the same routes work (the bootstrap key authenticates the call).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/alert-config")
                .header("content-type", "application/json")
                .header("x-api-key", bootstrap_key.clone())
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({"url": "https://hooks.example.com/tessera"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/anchor-config")
                .header("x-api-key", bootstrap_key)
                .header("x-tessera-admin", "admin-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn heavy_evidence_routes_have_their_own_budget() {
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    // An explicit budget on the state: no process-wide environment mutation.
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc,
        keys: Arc::new(tessera_broker::MemoryApiKeyStore::new()),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: Some(2),
    }));

    let get = |uri: &str| {
        let app = app.clone();
        let uri = uri.to_string();
        async move {
            app.oneshot(
                Request::builder()
                    .uri(uri)
                    .header("x-tessera-tenant", "acme")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    // Two exports are fine; the third hits the heavy-route budget.
    assert_eq!(get("/v1/export/tenant").await, StatusCode::OK);
    assert_eq!(get("/v1/export/tenant").await, StatusCode::OK);
    assert_eq!(
        get("/v1/export/tenant").await,
        StatusCode::TOO_MANY_REQUESTS,
        "the evidence budget must throttle after the configured limit"
    );
    // Other export routes share the same budget bucket per tenant.
    assert_eq!(
        get("/v1/export/chain/billing-agent").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn settings_changes_are_audited_and_reads_are_redacted() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope, NewKeyOptions};
    use tessera_broker::MemoryApiKeyStore;

    // An envelope so the alert token can be stored encrypted.
    let mut base = (*service(true).await).clone();
    base.secrets = Some(Arc::new(
        tessera_broker::secrets::Envelope::from_hex(&"55".repeat(32)).unwrap(),
    ));
    let svc = Arc::new(base);
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (_reader, reader_key) = keys
        .create(
            "acme",
            "reader",
            None,
            NewKeyOptions {
                scope: KeyScope {
                    capabilities: vec!["read".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_bootstrap, bootstrap_key) = keys
        .create("acme", "bootstrap", None, Default::default())
        .await
        .unwrap();
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys,
        demo_allow: false,
        admin_token: Some("admin-test".into()),
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    // Configure settings that contain secrets in their URLs.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/alert-config")
                .header("content-type", "application/json")
                .header("x-api-key", bootstrap_key.clone())
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({
                        "url": "https://hooks.slack.com/services/SECRET/PATH",
                        "token": "webhook-token",
                        "events": ["key.lifecycle"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/remediation-policy")
                .header("content-type", "application/json")
                .header("x-api-key", bootstrap_key.clone())
                .header("x-tessera-admin", "admin-test")
                .body(Body::from(
                    serde_json::json!({"template": "monitor"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Read-capable keys see host-only summaries, never the secret paths.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/alert-config")
                .header("x-api-key", reader_key.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "reader GET failed: {body}");
    // Host only: the path (where Slack embeds its secret) is never returned.
    assert_eq!(body["target"]["host"], "hooks.slack.com");
    assert!(
        body["target"].get("url").is_none(),
        "no full URL for readers"
    );
    assert_eq!(body["target"]["hasToken"], true);

    // The policy template is not a secret, so readers may see it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/remediation-policy")
                .header("x-api-key", reader_key.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The ledger records the settings changes with secrets redacted.
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["verified"], true);
    let changes: Vec<&serde_json::Value> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["kind"] == "setting.changed")
        .collect();
    assert_eq!(changes.len(), 2, "alert + remediation recorded");
    let alert_change = changes
        .iter()
        .find(|item| item["details"]["setting"] == "alert")
        .unwrap();
    assert_eq!(alert_change["details"]["action"], "set");
    let serialized = alert_change.to_string();
    assert!(
        !serialized.contains("SECRET") && !serialized.contains("webhook-token"),
        "the audit entry must not contain webhook secrets: {serialized}"
    );
    assert_eq!(alert_change["details"]["after"]["host"], "hooks.slack.com");
    let policy_change = changes
        .iter()
        .find(|item| item["details"]["setting"] == "remediation")
        .unwrap();
    assert_eq!(policy_change["details"]["after"]["template"], "monitor");
}

#[tokio::test]
async fn signed_snapshots_capture_settings_and_flag_changes() {
    use tessera_broker::remediation::RemediationPolicy;
    use tessera_broker::MemoryApiKeyStore;

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "tessera-settings-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir = Dir::new();
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    svc.remediation_policies
        .set(
            "acme",
            RemediationPolicy {
                template: "monitor".into(),
                template_version: Some(1),
                enabled: true,
                updated_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();

    let state = tessera_broker::http::AppState {
        service: svc.clone(),
        keys: Arc::new(MemoryApiKeyStore::new()),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    };

    // First snapshot: settings captured with a digest.
    let payload = tessera_broker::scheduler::integrity_snapshot_payload(&state, "acme")
        .await
        .unwrap()
        .expect("tenant has chains");
    let first_digest = payload["settings"]["digest"].as_str().unwrap().to_string();
    assert_eq!(payload["settings"]["remediation"]["template"], "monitor");
    svc.write_signed_snapshot(&dir.0, "integrity", "acme", payload.clone())
        .await
        .unwrap();

    // Change a setting: the next snapshot's digest differs and the diff flags the field.
    svc.remediation_policies
        .set(
            "acme",
            RemediationPolicy {
                template: "payments-integration".into(),
                template_version: Some(1),
                enabled: true,
                updated_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();
    let payload = tessera_broker::scheduler::integrity_snapshot_payload(&state, "acme")
        .await
        .unwrap()
        .unwrap();
    let second_digest = payload["settings"]["digest"].as_str().unwrap().to_string();
    assert_ne!(first_digest, second_digest);

    let previous = tessera_broker::authorize::AuthorizeService::previous_snapshot(&dir.0, "acme")
        .expect("previous snapshot on disk");
    let changes = tessera_broker::authorize::AuthorizeService::diff_snapshots(&previous, &payload);
    let settings_change = changes
        .iter()
        .find(|change| change["field"] == "settings.digest")
        .expect("settings change surfaced in the diff");
    assert_eq!(settings_change["from"], serde_json::json!(first_digest));
    assert_eq!(settings_change["to"], serde_json::json!(second_digest));
}

#[tokio::test]
async fn paged_bundles_import_page_by_page() {
    // A five-receipt chain exported as pages of two.
    let source = service(true).await;
    for amount in [10, 20, 30, 40, 50] {
        source.authorize("acme", request(amount)).await.unwrap();
    }
    let page1 = source
        .build_agent_export_page("acme", "billing-agent", Some(0), Some(2))
        .await
        .unwrap();
    let page2 = source
        .build_agent_export_page("acme", "billing-agent", Some(2), Some(2))
        .await
        .unwrap();
    let page3 = source
        .build_agent_export_page("acme", "billing-agent", Some(4), Some(2))
        .await
        .unwrap();
    assert_eq!(page1.manifest.next_from, Some(2));

    // Starting with page 2 is refused with a clear explanation (no silent mis-merge).
    let target = service(true).await;
    let err = target.import_chain("acme", &page2).await.unwrap_err();
    assert!(
        matches!(err, tessera_broker::BrokerError::Invalid(_)),
        "unexpected error: {err}"
    );
    assert!(err.to_string().contains("predecessor"), "error was: {err}");
    assert_eq!(target.chain.len("acme", "billing-agent").await.unwrap(), 0);

    // Importing the pages in order reconstructs the chain exactly (2 + 2 + 1 receipts).
    for (page, expected) in [(&page1, 2), (&page2, 2), (&page3, 1)] {
        let summary = target.import_chain("acme", page).await.unwrap();
        assert_eq!(summary["imported"], expected);
        assert_eq!(summary["skipped"], 0);
    }
    let imported = target.chain.chain("acme", "billing-agent").await.unwrap();
    let original = source.chain.chain("acme", "billing-agent").await.unwrap();
    assert_eq!(imported.len(), 5);
    for (local, expected) in imported.iter().zip(original.iter()) {
        assert_eq!(local.payload_hash, expected.payload_hash);
    }
    let domain = *target.signer.domain();
    assert!(
        tessera_broker::verify::verify_chain(&domain, &imported)
            .unwrap()
            .valid
    );

    // Replaying the same pages is a no-op.
    let summary = target.import_chain("acme", &page1).await.unwrap();
    assert_eq!(summary["imported"], 0);
    assert_eq!(summary["skipped"], 2);

    // The dry run reports page offsets, not genesis offsets.
    let report = target.import_report("acme", &page3).await.unwrap();
    assert_eq!(report["fromIndex"], 4);
    assert_eq!(report["matched"], 1);
    assert_eq!(report["missing"], 0);
}

#[tokio::test]
async fn dangerous_scope_patterns_are_rejected() {
    let svc = service(true).await;
    let app = app_of(svc);

    let create = |body: serde_json::Value| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/keys")
                        .header("content-type", "application/json")
                        .header("x-tessera-tenant", "acme")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // `stripe*` would also grant `stripeplayground:...`: refused with the offending value.
    let (status, body) = create(serde_json::json!({
        "name": "sloppy",
        "allowedResources": ["stripe*"]
    }))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["invalid"][0], "resource pattern 'stripe*'");

    // Relative proxy paths are refused too.
    let (status, body) = create(serde_json::json!({
        "name": "sloppy-paths",
        "allowedProxyPaths": ["refunds*"]
    }))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["invalid"][0], "proxy path 'refunds*'");

    // Correctly scoped patterns are accepted.
    let (status, _) = create(serde_json::json!({
        "name": "precise",
        "allowedResources": ["stripe:*", "aws:s3:Get*", "*"],
        "allowedProxyPaths": ["/v1/refunds*", "/v1/refunds"]
    }))
    .await;
    assert_eq!(status, StatusCode::OK);

    // The same validation guards scope updates.
    let created = create(serde_json::json!({"name": "evolving", "allowedCapabilities": ["read"]}))
        .await
        .1;
    let id = created["record"]["id"].as_str().unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/keys/{id}"))
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"allowedResources": ["github*"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn metrics_token_gate_is_opt_in() {
    // Off by default: the public endpoint answers.
    let svc = service(true).await;
    let app = app_of(svc.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // With a token configured, only the bearer token is accepted (compared in constant time).
    std::env::set_var("METRICS_TOKEN", "metrics-secret");
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let wrong = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header("authorization", "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let allowed = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header("authorization", "Bearer metrics-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    std::env::remove_var("METRICS_TOKEN");
}

#[tokio::test]
async fn chain_reads_are_bounded_and_pageable() {
    let svc = service(true).await;
    for amount in [10, 20, 30, 40, 50] {
        svc.authorize("acme", request(amount)).await.unwrap();
    }
    // Build the app with an explicit small default so no process-wide env is involved.
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys: Arc::new(tessera_broker::MemoryApiKeyStore::new()),
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 2,
        heavy_route_rate_limit: None,
    }));

    let get = |uri: &str| {
        let app = app.clone();
        let uri = uri.to_string();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("x-tessera-tenant", "acme")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // Default: the newest page, with the full length and a cursor backwards.
    let (status, body) = get("/v1/chain/billing-agent").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["length"], 5);
    assert_eq!(body["returned"], 2);
    assert_eq!(body["from"], 3);
    assert_eq!(body["hasMore"], false);
    assert_eq!(body["verified"], true);

    // Explicit page from genesis.
    let (_, first) = get("/v1/chain/billing-agent?from=0&limit=2").await;
    assert_eq!(first["from"], 0);
    assert_eq!(first["returned"], 2);
    assert_eq!(first["hasMore"], true);
    assert_eq!(first["nextFrom"], 2);

    // Paging forwards walks the chain without gaps or repeats.
    let mut seen = Vec::new();
    let mut next = Some(0usize);
    while let Some(from) = next {
        let (_, page) = get(&format!("/v1/chain/billing-agent?from={from}&limit=2")).await;
        seen.extend(
            page["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["payload_hash"].as_str().unwrap().to_string()),
        );
        next = page["nextFrom"].as_u64().map(|value| value as usize);
    }
    let full = svc.chain.chain("acme", "billing-agent").await.unwrap();
    let expected: Vec<String> = full
        .iter()
        .map(|entry| entry.payload_hash.clone())
        .collect();
    assert_eq!(seen, expected);

    // An oversized limit is clamped, and a cursor past the end returns nothing.
    let (_, clamped) = get("/v1/chain/billing-agent?from=0&limit=999999").await;
    assert_eq!(clamped["returned"], 5);
    let (_, beyond) = get("/v1/chain/billing-agent?from=99").await;
    assert_eq!(beyond["returned"], 0);
}

#[tokio::test]
async fn anchor_listing_is_bounded() {
    use tessera_broker::anchoring::AnchorRecord;

    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    for index in 0..5 {
        svc.anchors
            .record(AnchorRecord {
                id: format!("a{index}"),
                tenant: "acme".into(),
                agent: "billing-agent".into(),
                merkle_root: format!("0x{}", hex::encode([index as u8; 32])),
                count: 1,
                chain_id: 84532,
                contract: "0x0000000000000000000000000000000000000001".into(),
                tx_hash: None,
                status: "confirmed".into(),
                block_number: None,
                created_at: format!("2026-09-1{}T00:00:00Z", index + 1),
            })
            .await
            .unwrap();
    }
    let app = app_of(svc);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/anchors?limit=2")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["count"], 5);
    assert_eq!(body["returned"], 2);
    assert_eq!(body["hasMore"], true);
    // Newest first.
    assert_eq!(body["items"][1]["id"], "a4");
}

#[tokio::test]
async fn record_uses_indexed_lookups() {
    let svc = service(true).await;
    let allowed = svc.authorize("acme", request(100)).await.unwrap();
    let first = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: allowed.receipt_id.clone(),
                result_hash: rh(0xdd),
                status: Some("ok".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!first.duplicate);
    assert_eq!(first.chain_length, 2);

    // Replaying the outcome reports the same receipt as a duplicate (via `find_by_prev`).
    let again = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: allowed.receipt_id.clone(),
                result_hash: rh(0xdd),
                status: Some("ok".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(again.duplicate);
    assert_eq!(again.receipt_id, first.receipt_id);
    assert_eq!(again.chain_length, 2);

    // A successor authorization also links to the previous receipt (`prev == older`), so the
    // duplicate check must look for an *outcome* (result hash present), not any successor.
    let older = svc.authorize("acme", request(200)).await.unwrap();
    let newer = svc.authorize("acme", request(300)).await.unwrap();

    // A late outcome is allowed: it links to its authorization by id and to the current
    // head by `prev`, so a later authorization does not make the outcome unrecordable.
    let late = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: older.receipt_id.clone(),
                result_hash: rh(0x01),
                status: Some("ok".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!late.duplicate);
    assert_eq!(
        late.receipt.authorization_receipt_id.as_deref(),
        Some(older.receipt_id.as_str())
    );
    assert_eq!(
        late.receipt.prev.as_deref(),
        Some(newer.receipt_id.as_str())
    );

    // The head (newest) authorization records normally, and its replay is a duplicate.
    let recorded_newer = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: newer.receipt_id.clone(),
                result_hash: rh(0x02),
                status: Some("ok".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!recorded_newer.duplicate);
    assert_eq!(
        recorded_newer.receipt.call.result_hash.as_deref(),
        Some(rh(0x02).as_str())
    );
    let replay_newer = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing-agent".into(),
                receipt_id: newer.receipt_id.clone(),
                result_hash: rh(0x02),
                status: Some("ok".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(replay_newer.duplicate);
    assert_eq!(replay_newer.receipt_id, recorded_newer.receipt_id);

    // An unknown authorization is still a 404, and a missing agent is too.
    let err = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "nobody".into(),
                receipt_id: allowed.receipt_id.clone(),
                result_hash: rh(0xdd),
                status: None,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::NotFound(_)));
}

#[tokio::test]
async fn write_routes_require_the_right_authorization() {
    use tessera_broker::auth::{ApiKeyStore, KeyScope, NewKeyOptions};
    use tessera_broker::MemoryApiKeyStore;

    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    let keys = Arc::new(MemoryApiKeyStore::new());
    let scoped = |capabilities: Vec<&str>| KeyScope {
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        ..Default::default()
    };
    let (_bootstrap, bootstrap_key) = keys
        .create("acme", "bootstrap", None, Default::default())
        .await
        .unwrap();
    let (_proxy_only, proxy_only_key) = keys
        .create(
            "acme",
            "proxy",
            None,
            NewKeyOptions {
                scope: scoped(vec!["proxy"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_reader, reader_key) = keys
        .create(
            "acme",
            "reader",
            None,
            NewKeyOptions {
                scope: scoped(vec!["read"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let app = tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service: svc.clone(),
        keys,
        demo_allow: false,
        admin_token: Some("admin-test".into()),
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let call =
        |key: String, method: &'static str, uri: String, body: serde_json::Value, admin: bool| {
            let app = app.clone();
            async move {
                let mut builder = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("x-api-key", key);
                if admin {
                    builder = builder.header("x-tessera-admin", "admin-test");
                }
                app.oneshot(
                    builder
                        .body(if body.is_null() {
                            Body::empty()
                        } else {
                            Body::from(body.to_string())
                        })
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };

    // Import mutates the chain: non-admin refused, admin allowed (dry run needs a bundle).
    let bundle = svc.export_chain("acme", "billing-agent").await.unwrap();
    let bundle = serde_json::to_value(&bundle).unwrap();
    assert_eq!(
        call(
            reader_key.clone(),
            "POST",
            "/v1/import?dryRun=true".into(),
            bundle.clone(),
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            bootstrap_key.clone(),
            "POST",
            "/v1/import?dryRun=true".into(),
            bundle,
            true
        )
        .await,
        StatusCode::OK
    );

    // Anchor submission is a write: needs `authorize`, not `read`.
    assert_eq!(
        call(
            reader_key.clone(),
            "POST",
            "/v1/chain/billing-agent/anchor/submit".into(),
            serde_json::json!({}),
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            proxy_only_key.clone(),
            "POST",
            "/v1/chain/billing-agent/anchor/submit".into(),
            serde_json::json!({}),
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // Integrity and revocations listings require `read`.
    assert_eq!(
        call(
            proxy_only_key.clone(),
            "GET",
            "/v1/integrity".into(),
            serde_json::Value::Null,
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            reader_key.clone(),
            "GET",
            "/v1/integrity".into(),
            serde_json::Value::Null,
            false
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        call(
            proxy_only_key.clone(),
            "GET",
            "/v1/revocations".into(),
            serde_json::Value::Null,
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // Revocation is an admin action.
    assert_eq!(
        call(
            reader_key,
            "POST",
            "/v1/revoke".into(),
            serde_json::json!({"target": "billing-agent", "kind": "agent"}),
            false
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            bootstrap_key,
            "POST",
            "/v1/revoke".into(),
            serde_json::json!({"target": "billing-agent", "kind": "agent"}),
            true
        )
        .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn agent_ids_are_validated_and_archive_names_are_safe() {
    let svc = service(true).await;

    // Path-traversal and control characters are rejected at the boundary.
    for bad in ["../evil", "a/b", "a\\b", "..", ".hidden", "", "a\u{1}b"] {
        let mut req = request(10);
        req.agent_id = bad.to_string();
        assert!(
            matches!(
                svc.authorize("acme", req).await.unwrap_err(),
                tessera_broker::BrokerError::Invalid(_)
            ),
            "agent id {bad:?} must be rejected"
        );
    }
    // Long ids are rejected too (filenames and ledger fields stay bounded).
    let mut req = request(10);
    req.agent_id = "a".repeat(129);
    assert!(matches!(
        svc.authorize("acme", req).await.unwrap_err(),
        tessera_broker::BrokerError::Invalid(_)
    ));

    // Valid ids with punctuation are accepted, and archive entry names are sanitised.
    let mut ok = request(10);
    ok.agent_id = "agent:1@host".into();
    svc.authorize("acme", ok).await.unwrap();
    let bundle = svc.export_tenant("acme").await.unwrap();
    let bytes = tessera_broker::export::build_tenant_archive(&bundle, "tessera-verify --archive .")
        .unwrap();
    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    let mut agent_entries = Vec::new();
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().to_string();
        if name.starts_with("agents/") {
            agent_entries.push(name);
        }
    }
    assert_eq!(agent_entries.len(), 1);
    assert!(
        !agent_entries[0].contains(':')
            && !agent_entries[0].contains('@')
            && !agent_entries[0].contains(".."),
        "archive entry must be sanitised: {agent_entries:?}"
    );
}

#[tokio::test]
async fn empty_paged_exports_verify_and_import_as_noops() {
    let svc = service(true).await;
    svc.authorize("acme", request(10)).await.unwrap();
    svc.authorize("acme", request(20)).await.unwrap();

    // A page starting at the chain end is valid evidence: no receipts, predecessor named.
    let page = svc
        .build_agent_export_page("acme", "billing-agent", Some(2), Some(2))
        .await
        .unwrap();
    assert!(page.receipts.is_empty());
    assert_eq!(page.manifest.from_index, 2);
    assert!(page.manifest.prev_before.is_some());
    assert!(page.verify().unwrap(), "an empty trailing page must verify");

    // Importing it changes nothing and reports success.
    let summary = svc.import_chain("acme", &page).await.unwrap();
    assert_eq!(summary["imported"], 0);
    assert_eq!(summary["skipped"], 0);
    assert_eq!(svc.chain.len("acme", "billing-agent").await.unwrap(), 2);
}

#[tokio::test]
async fn evidence_pruning_handles_hyphenated_tenants() {
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "tessera-hyphen-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir = Dir::new();
    let svc = service(true).await;
    svc.authorize("acme-prod", request(10)).await.unwrap();

    // Old artefacts with a hyphenated tenant id must be recognised (tenant = "acme-prod").
    std::fs::write(
        dir.0
            .join("tessera-export-acme-prod-20200101T000000Z-deadbeef.tar.gz"),
        b"old",
    )
    .unwrap();
    std::fs::write(
        dir.0
            .join("integrity-acme-prod-20200101T000000Z-cafebabe.json"),
        b"{}",
    )
    .unwrap();
    let report = svc.integrity_report("acme-prod").await.unwrap();
    let (fresh, _) = svc
        .write_signed_snapshot(&dir.0, "integrity", "acme-prod", report)
        .await
        .unwrap();

    let pruned = svc.prune_evidence(&dir.0, 30).await.unwrap();
    assert_eq!(pruned, 2, "old archive + old snapshot");
    assert!(fresh.exists(), "the newest snapshot is always kept");
    assert!(!dir
        .0
        .join("tessera-export-acme-prod-20200101T000000Z-deadbeef.tar.gz")
        .exists());
}

#[tokio::test]
async fn alert_config_reads_do_not_require_decrypting_the_token() {
    use tessera_broker::alerts::AlertTarget;

    // A broker that once had an encryption key, now missing it (rotation/restore scenario).
    let mut base = (*service(true).await).clone();
    let envelope = Arc::new(tessera_broker::secrets::Envelope::from_hex(&"66".repeat(32)).unwrap());
    base.secrets = Some(envelope);
    let svc = Arc::new(base);
    svc.set_alert_target(
        "acme",
        AlertTarget {
            url: "https://hooks.example.com/tessera".into(),
            token: Some("stored-token".into()),
            events: vec![],
            auto_ack_below: None,
        },
    )
    .await
    .unwrap();

    // Simulate losing the encryption key: reads must still work (and never decrypt).
    let mut without_key = (*svc).clone();
    without_key.secrets = None;
    let svc = Arc::new(without_key);

    let stored = svc.alert_router.target("acme").await.unwrap().unwrap();
    assert!(tessera_broker::secrets::is_encrypted(
        stored.token.as_deref().unwrap()
    ));
    // The decryption-dependent helper fails, as expected...
    assert!(svc.alert_target("acme").await.is_err());
    // ...but the HTTP read path (which only needs `hasToken`) succeeds.
    let app = app_of(svc);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/alert-config")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["target"]["hasToken"], true);
}

#[tokio::test]
async fn policy_creation_is_capped_but_updates_are_not() {
    let svc = service(true).await;
    let app = app_of(svc);

    let put = |id: String, policy: serde_json::Value| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/policies/{id}"))
                    .header("content-type", "application/json")
                    .header("x-tessera-tenant", "acme")
                    .body(Body::from(policy.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };
    let policy = |name: &str| {
        serde_json::json!({
            "version": 1,
            "name": name,
            "grants": [{"resource": "stripe:*"}]
        })
    };

    // The builder already has one policy; add up to the cap.
    for index in 0..99 {
        assert_eq!(put(format!("p{index}"), policy("p")).await, StatusCode::OK);
    }
    assert_eq!(
        put("one-too-many".into(), policy("p")).await,
        StatusCode::BAD_REQUEST
    );
    // Updating an existing policy is still allowed at the cap (with a version bump).
    let mut updated = policy("updated");
    updated["version"] = serde_json::json!(2);
    assert_eq!(put("p0".into(), updated).await, StatusCode::OK);
}

#[tokio::test]
async fn tool_pinning_refuses_silent_redefinitions() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    let definition = serde_json::json!({
        "name": "stripe.refunds.create",
        "description": "Create a refund",
        "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}},
        "annotations": {"destructiveHint": false}
    });
    let approved_hash = tessera_broker::tool_pins::definition_hash(&definition);

    // Admin approves the definition.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/tools/stripe.refunds.create")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"definition": definition}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["pin"]["definitionHash"], approved_hash);

    let authorize = |hash: Option<&str>| {
        let app = app.clone();
        let mut payload = serde_json::json!({
            "agentId": "billing-agent",
            "userId": "u1",
            "tool": "stripe.refunds.create",
            "intent": "refund",
            "args": {"charge": "ch_1", "amount": 100}
        });
        if let Some(hash) = hash {
            payload["toolSchemaHash"] = serde_json::json!(hash);
        }
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/authorize")
                        .header("content-type", "application/json")
                        .header("x-tessera-tenant", "acme")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
            .unwrap();
            (status, body)
        }
    };

    // Matches the approved definition: allowed, and the hash is recorded in the receipt.
    let (status, body) = authorize(Some(&approved_hash)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["receipt"]["call"]["toolHash"], approved_hash,
        "the receipt must bind the tool definition that was approved"
    );

    // Missing hash for a pinned tool: refused.
    let (status, body) = authorize(None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("toolSchemaHash is required"));

    // A silently changed definition (rug pull) is refused and audited.
    let drifted = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let (status, body) = authorize(Some(drifted)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().unwrap().contains("rug pull"));

    let log = svc.key_event_log("acme", None, None).await.unwrap();
    assert_eq!(log["verified"], true);
    let kinds: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"tool.pinned"));
    assert!(kinds.contains(&"tool.drift"));
    let drift = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "tool.drift")
        .unwrap();
    assert_eq!(drift["details"]["expected"], approved_hash);
    assert_eq!(drift["details"]["received"], drifted);

    // Re-approving the new definition accepts it (review is explicit, never automatic).
    let changed = serde_json::json!({
        "name": "stripe.refunds.create",
        "description": "Create a refund (v2)",
        "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}}
    });
    let changed_hash = tessera_broker::tool_pins::definition_hash(&changed);
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/tools/stripe.refunds.create")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(
                    serde_json::json!({"definition": changed}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorize(Some(&changed_hash)).await.0, StatusCode::OK);
    // The old hash is now the drifted one.
    assert_eq!(
        authorize(Some(&approved_hash)).await.0,
        StatusCode::FORBIDDEN
    );

    // Listing requires read capability and exposes the approved definition.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/tools")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["count"], 1);
    assert_eq!(body["items"][0]["definitionHash"], changed_hash);
}

#[tokio::test]
async fn tool_pins_upsert_and_delete() {
    use tessera_broker::tool_pins::{ToolPin, ToolPinStore};

    let store = tessera_broker::tool_pins::MemoryToolPins::new();
    let pin = |hash: &str| ToolPin {
        tenant: "acme".into(),
        tool: "t".into(),
        definition_hash: hash.into(),
        definition: serde_json::json!({"name": "t"}),
        created_at: "2026-09-18T00:00:00Z".into(),
        updated_at: "2026-09-18T00:00:00Z".into(),
    };
    store.set(pin("0x1")).await.unwrap();
    store.set(pin("0x2")).await.unwrap();
    assert_eq!(store.list("acme").await.unwrap().len(), 1);
    assert_eq!(
        store
            .get("acme", "t")
            .await
            .unwrap()
            .unwrap()
            .definition_hash,
        "0x2"
    );
    assert!(store.delete("acme", "t").await.unwrap());
    assert!(!store.delete("acme", "t").await.unwrap());
    assert!(store.list("acme").await.unwrap().is_empty());
}

#[tokio::test]
async fn policy_changes_are_audited_in_the_ledger() {
    let svc = service(true).await;
    let app = app_of(svc.clone());

    let policy = serde_json::json!({
        "id": "p-audit",
        "version": 1,
        "name": "audit",
        "grants": [{
            "resource": "stripe:refunds.create",
            "constraints": [{
                "type": "max_number",
                "field": "amount",
                "value": 100
            }]
        }]
    });
    let put = |app: axum::Router, body: serde_json::Value| async move {
        app.oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/policies/p-audit")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    };
    assert_eq!(
        put(app.clone(), policy.clone()).await.status(),
        StatusCode::OK
    );

    let log = svc.key_event_log("acme", None, None).await.unwrap();
    let changed: Vec<&serde_json::Value> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["kind"] == "policy.changed")
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["details"]["action"], "set");
    assert_eq!(changed[0]["details"]["version"], 1);
    let first_digest = changed[0]["details"]["digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(first_digest.starts_with("0x"));

    // Editing the policy records a different digest.
    let mut edited = policy.clone();
    edited["version"] = serde_json::json!(2);
    edited["grants"][0]["constraints"][0]["value"] = serde_json::json!(250);
    assert_eq!(put(app.clone(), edited).await.status(), StatusCode::OK);
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    let changed: Vec<&serde_json::Value> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["kind"] == "policy.changed")
        .collect();
    assert_eq!(changed.len(), 2);
    assert_ne!(changed[1]["details"]["digest"], first_digest.as_str());

    // Deleting records what was removed.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/policies/p-audit")
                .header("x-tessera-tenant", "acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let log = svc.key_event_log("acme", None, None).await.unwrap();
    let deleted = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "policy.changed" && item["details"]["action"] == "deleted")
        .expect("deletion must be audited");
    assert_eq!(deleted["details"]["policyId"], "p-audit");
    assert_eq!(
        deleted["details"]["digestBefore"],
        changed[1]["details"]["digest"]
    );
    assert_eq!(log["verified"], true);
}
