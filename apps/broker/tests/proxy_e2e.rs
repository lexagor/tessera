//! Grant-proxy end-to-end tests against a mock upstream (no live Stripe calls).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::any;
use axum::{Json, Router};
use serde_json::{json, Value};

use tessera_broker::authorize::{AuthorizeRequest, AuthorizeService};
use tessera_broker::canonical;
use tessera_broker::chain::MemoryChainStore;
use tessera_broker::config::StripeConfig;
use tessera_broker::issuers::stripe::StripeIssuer;
use tessera_broker::issuers::{CredentialMaterial, IssuerRegistry};
use tessera_broker::policy::{demo_policy, InMemoryPolicyStore};
use tessera_broker::proxy::ProxyRequest;
use tessera_broker::receipt::ReceiptSigner;

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
const SECRET: &str = "rk_test_secret";

/// Mock upstream that echoes the Authorization header and body it received.
async fn echo(headers: HeaderMap, body: Bytes) -> Json<Value> {
    Json(json!({
        "auth": headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""),
        "body": String::from_utf8_lossy(&body),
    }))
}

/// Mock upstream that returns an oversized response.
async fn huge() -> String {
    "x".repeat(2 * 1024 * 1024)
}

async fn fail() -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": "provider failed" })),
    )
}

async fn slow() -> Json<Value> {
    tokio::time::sleep(Duration::from_millis(300)).await;
    Json(json!({ "ok": true }))
}

async fn spawn_upstream() -> String {
    let app = Router::new()
        .route("/v1/refunds", any(echo))
        .route("/v1/fail", any(fail))
        .route("/v1/huge", any(huge))
        .route("/v1/slow", any(slow));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn service(api_base: String) -> Arc<AuthorizeService> {
    service_with_egress(
        api_base,
        tessera_broker::netguard::EgressGuard::permissive(),
    )
}

fn service_with_egress(
    api_base: String,
    egress: tessera_broker::netguard::EgressGuard,
) -> Arc<AuthorizeService> {
    service_with_options(api_base, egress, reqwest::Client::new())
}

fn service_with_http(api_base: String, http: reqwest::Client) -> Arc<AuthorizeService> {
    service_with_options(
        api_base,
        tessera_broker::netguard::EgressGuard::permissive(),
        http,
    )
}

fn service_with_options(
    api_base: String,
    egress: tessera_broker::netguard::EgressGuard,
    http: reqwest::Client,
) -> Arc<AuthorizeService> {
    let signer =
        Arc::new(ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 84532, ZERO_ADDR).unwrap());
    let mut keys = HashMap::new();
    keys.insert("refunds_create".to_string(), SECRET.to_string());
    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(StripeIssuer::new(StripeConfig {
        restricted_keys: keys,
        api_base,
    })));
    Arc::new(AuthorizeService {
        policies: Arc::new(InMemoryPolicyStore::new()),
        issuers: Arc::new(issuers),
        authority: Default::default(),
        signer,
        chain: Arc::new(MemoryChainStore::new()),
        telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        anchor: None,
        anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: Arc::new(tessera_broker::anchoring::MemoryAnchorTargetStore::new()),
        secrets: None,
        rpc_policy: Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: Arc::new(egress),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min: None,
        retention_days: 90,
        anchor_confirmations: 12,
        anchor_reorg_grace_secs: 300,
        revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http,
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
        demo_policy: Some(demo_policy()),
    })
}

async fn authorize_grant(svc: &AuthorizeService, args: Value) -> (String, String) {
    let (grant_id, args_hash, _) = authorize_grant_with_receipt(svc, "acme", args).await;
    (grant_id, args_hash)
}

async fn authorize_grant_for(
    svc: &AuthorizeService,
    tenant: &str,
    args: Value,
) -> (String, String) {
    let (grant_id, args_hash, _) = authorize_grant_with_receipt(svc, tenant, args).await;
    (grant_id, args_hash)
}

async fn authorize_grant_with_receipt(
    svc: &AuthorizeService,
    tenant: &str,
    args: Value,
) -> (String, String, tessera_broker::authorize::AuthorizeResponse) {
    let auth = svc
        .authorize(
            tenant,
            AuthorizeRequest {
                agent_id: "billing".into(),
                user_id: "u".into(),
                tool: "stripe.refunds.create".into(),
                intent: "refund".into(),
                args: args.clone(),
                tool_schema_hash: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let grant_id = match auth
        .credential
        .as_ref()
        .map(|credential| &credential.material)
    {
        Some(CredentialMaterial::Grant {
            grant_id,
            proxy_required,
        }) => {
            assert!(*proxy_required);
            grant_id.clone()
        }
        other => panic!("expected grant, got {other:?}"),
    };
    (grant_id, canonical::hash_json(&args), auth)
}

#[tokio::test]
async fn proxy_records_a_broker_observed_outcome() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash, auth) =
        authorize_grant_with_receipt(&svc, "acme", json!({ "amount": 4200 })).await;

    let response = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: Some("amount=4200".into()),
            },
        )
        .await
        .unwrap();

    assert!(response.outcome_recorded);
    assert_eq!(
        response.authorization_receipt_id.as_deref(),
        Some(auth.receipt_id.as_str())
    );
    assert_eq!(response.action_id.as_deref(), Some(auth.action_id.as_str()));
    let outcome = response.outcome_receipt.expect("outcome receipt");
    assert_eq!(
        outcome.authorization_receipt_id.as_deref(),
        Some(auth.receipt_id.as_str())
    );
    assert_eq!(outcome.prev.as_deref(), Some(auth.receipt_id.as_str()));
    assert_eq!(
        outcome.outcome.as_ref().unwrap().source.as_deref(),
        Some("broker_observed")
    );
    assert_eq!(outcome.outcome.as_ref().unwrap().status, "success");

    let chain = svc.chain.chain("acme", "billing").await.unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].payload_hash, response.outcome_receipt_id.unwrap());
    assert!(svc.verify_chain("acme", "billing").await.unwrap());
}

#[tokio::test]
async fn agent_cannot_self_report_a_grant_outcome() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (_grant_id, _args_hash, auth) =
        authorize_grant_with_receipt(&svc, "acme", json!({ "amount": 1 })).await;
    let error = svc
        .record(
            "acme",
            tessera_broker::authorize::RecordRequest {
                agent_id: "billing".into(),
                receipt_id: auth.receipt_id,
                result_hash: format!("0x{}", "33".repeat(32)),
                status: Some("success".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("broker-held grants"), "{error}");
}

#[tokio::test]
async fn late_proxy_outcome_links_to_its_authorization() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash, first) =
        authorize_grant_with_receipt(&svc, "acme", json!({ "amount": 1 })).await;
    let second = svc
        .authorize(
            "acme",
            AuthorizeRequest {
                agent_id: "billing".into(),
                user_id: "u".into(),
                tool: "stripe.refunds.create".into(),
                intent: "refund".into(),
                args: json!({ "amount": 2 }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let response = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await
        .unwrap();

    let outcome = response.outcome_receipt.expect("outcome receipt");
    assert_eq!(outcome.prev.as_deref(), Some(second.receipt_id.as_str()));
    assert_eq!(
        outcome.authorization_receipt_id.as_deref(),
        Some(first.receipt_id.as_str())
    );
    assert!(svc.verify_chain("acme", "billing").await.unwrap());
}

#[tokio::test]
async fn upstream_failure_is_recorded_as_failure() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash, _) =
        authorize_grant_with_receipt(&svc, "acme", json!({ "amount": 9 })).await;

    let response = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/fail".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.status, 502);
    assert!(response.outcome_recorded);
    let outcome = response.outcome_receipt.unwrap();
    assert_eq!(outcome.outcome.unwrap().status, "failure");
}

#[tokio::test]
async fn proxy_forwards_with_broker_held_secret() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 4200 })).await;

    let resp = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id: grant_id.clone(),
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: Some("amount=4200".into()),
            },
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    let echoed: Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(echoed["auth"], format!("Bearer {SECRET}"));
    assert_eq!(echoed["body"], "amount=4200");
}

#[tokio::test]
async fn proxy_provider_timeout_fails_closed() {
    let base = spawn_upstream().await;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    let svc = service_with_http(base, http);
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;

    let err = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "GET".into(),
                path: "/v1/slow".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await;
    assert!(matches!(err, Err(tessera_broker::BrokerError::Issuer(_))));
}

#[tokio::test]
async fn proxy_is_single_use() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;

    let make = || ProxyRequest {
        grant_id: grant_id.clone(),
        args_hash: args_hash.clone(),
        method: "POST".into(),
        path: "/v1/refunds".into(),
        query: vec![],
        content_type: None,
        body: None,
    };

    assert!(svc.proxy("acme", make()).await.is_ok());
    assert!(svc.proxy("acme", make()).await.is_err()); // consumed
}

#[tokio::test]
async fn proxy_rejects_mismatched_args_hash() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, _args_hash) = authorize_grant(&svc, json!({ "amount": 4200 })).await;

    let err = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash: "0xnot-the-bound-hash".into(),
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await;
    assert!(matches!(err, Err(tessera_broker::BrokerError::Denied(_))));
}

#[tokio::test]
async fn revoked_grant_blocks_proxy() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;

    let outcome = svc
        .revoke("acme", &grant_id, "grant", Some("leak".into()))
        .await
        .unwrap();
    assert_eq!(outcome.provider.as_deref(), Some("stripe"));
    assert_eq!(outcome.grant_revoked, Some(true));

    let err = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await;
    assert!(matches!(err, Err(tessera_broker::BrokerError::Denied(_))));
}

#[tokio::test]
async fn oversized_provider_response_is_rejected() {
    let base = spawn_upstream().await;
    let svc = service(base);
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;

    let err = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "GET".into(),
                path: "/v1/huge".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await;
    assert!(matches!(err, Err(tessera_broker::BrokerError::Issuer(_))));
}

#[tokio::test]
async fn egress_allowlist_blocks_unapproved_provider_hosts() {
    let base = spawn_upstream().await;

    // A strict guard that does not list the mock upstream blocks the proxied call.
    let strict = service_with_egress(
        base.clone(),
        tessera_broker::netguard::EgressGuard::new(vec!["api.stripe.com".into()]),
    );
    let (grant_id, args_hash) = authorize_grant(&strict, json!({ "amount": 1 })).await;
    let err = strict
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await;
    assert!(matches!(err, Err(tessera_broker::BrokerError::Invalid(_))));

    // The same call succeeds when the host is allowlisted.
    let host = base.trim_start_matches("http://").to_string();
    let allowed = service_with_egress(base, tessera_broker::netguard::EgressGuard::new(vec![host]));
    let (grant_id, args_hash) = authorize_grant(&allowed, json!({ "amount": 1 })).await;
    assert!(allowed
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn proxy_enforces_the_key_scope_on_the_grant_resource() {
    use tessera_broker::auth::KeyScope;

    let base = spawn_upstream().await;
    let svc = service(base);

    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;
    let foreign_scope = KeyScope {
        resources: vec!["aws:*".into()],
        agents: vec![],
        capabilities: vec![],
        proxy_paths: vec![],
    };
    let err = svc
        .proxy_scoped(
            "acme",
            ProxyRequest {
                grant_id: grant_id.clone(),
                args_hash: args_hash.clone(),
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
            Some(&foreign_scope),
        )
        .await
        .expect_err("scope must block the redemption");
    assert!(matches!(err, tessera_broker::BrokerError::Denied(_)));

    // A refused redemption must not consume the single-use grant.
    let matching_scope = KeyScope {
        resources: vec!["stripe:*".into()],
        agents: vec![],
        capabilities: vec![],
        proxy_paths: vec![],
    };
    assert!(svc
        .proxy_scoped(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
            Some(&matching_scope),
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn proxy_calls_reserve_provider_capacity() {
    let base = spawn_upstream().await;
    let mut svc = (*service(base)).clone();
    svc.quota = Arc::new(tessera_broker::quota::QuotaManager::new(4, 2));
    let svc = Arc::new(svc);

    // Issuance itself is covered: the permit is released once the credential exists.
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;

    // Hold acme's entire per-tenant reservation, as an in-flight call would.
    let held = svc.quota.acquire("stripe", "acme").unwrap();
    let held2 = svc.quota.acquire("stripe", "acme").unwrap();
    let err = svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await
        .expect_err("throttled while at capacity");
    assert!(matches!(err, tessera_broker::BrokerError::Throttled(_)));

    // Another tenant is unaffected by acme's usage (its own grant + reservation).
    let (grant_id, args_hash) = authorize_grant_for(&svc, "other", json!({ "amount": 1 })).await;
    assert!(svc
        .proxy(
            "other",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await
        .is_ok());

    // Releasing a reservation lets acme's call through.
    drop(held);
    let (grant_id, args_hash) = authorize_grant(&svc, json!({ "amount": 1 })).await;
    assert!(svc
        .proxy(
            "acme",
            ProxyRequest {
                grant_id,
                args_hash,
                method: "POST".into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            },
        )
        .await
        .is_ok());
    drop(held2);
}
