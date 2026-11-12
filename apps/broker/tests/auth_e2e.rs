//! Auth middleware + API-key lifecycle tests.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use tessera_broker::auth::{ApiKeyStore, MemoryApiKeyStore};
use tessera_broker::authorize::AuthorizeService;
use tessera_broker::chain::MemoryChainStore;
use tessera_broker::issuers::mock::MockIssuer;
use tessera_broker::issuers::IssuerRegistry;
use tessera_broker::policy::{demo_policy, InMemoryPolicyStore};
use tessera_broker::receipt::ReceiptSigner;
use tessera_broker::AppState;

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

fn service() -> Arc<AuthorizeService> {
    let signer =
        Arc::new(ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 84532, ZERO_ADDR).unwrap());
    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(MockIssuer::new("stripe")));
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
        egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min: None,
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

fn app(state: Arc<AppState>) -> Router {
    tessera_broker::http::app(state)
}

fn state(keys: Arc<MemoryApiKeyStore>, demo_allow: bool) -> Arc<AppState> {
    Arc::new(AppState {
        service: service(),
        keys,
        demo_allow,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    })
}

fn authorize_body() -> String {
    serde_json::json!({
        "agentId": "a1", "userId": "u1",
        "tool": "stripe.refunds.create", "intent": "refund",
        "args": { "amount": 1 }
    })
    .to_string()
}

async fn call(app: &Router, headers: &[(&str, &str)]) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/authorize")
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(authorize_body())).unwrap())
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn missing_key_is_unauthorized() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = app(state(keys, false));
    assert_eq!(call(&app, &[]).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_key_and_api_key_header_authorize() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (_record, key) = keys
        .create("acme", "test", None, Default::default())
        .await
        .unwrap();
    let app = app(state(keys, false));

    let bearer = format!("Bearer {key}");
    assert_eq!(
        call(&app, &[("authorization", &bearer)]).await,
        StatusCode::OK
    );
    assert_eq!(call(&app, &[("x-api-key", &key)]).await, StatusCode::OK);
}

#[tokio::test]
async fn invalid_key_is_unauthorized() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = app(state(keys, false));
    assert_eq!(
        call(&app, &[("authorization", "Bearer tsk_not_a_real_key")]).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revoked_key_is_unauthorized() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (record, key) = keys
        .create("acme", "test", None, Default::default())
        .await
        .unwrap();
    let app = app(state(keys.clone(), false));

    let bearer = format!("Bearer {key}");
    assert_eq!(
        call(&app, &[("authorization", &bearer)]).await,
        StatusCode::OK
    );

    assert_eq!(
        keys.revoke("acme", &record.id, None).await.unwrap(),
        tessera_broker::auth::MutateOutcome::Done(())
    );
    assert_eq!(
        call(&app, &[("authorization", &bearer)]).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rate_limit_throttles_tenant() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(AppState {
        service: service(),
        keys,
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: Some(2),
        public_rate_limit_per_min: None,
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    assert_eq!(
        call(&app, &[("x-tessera-tenant", "acme")]).await,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, &[("x-tessera-tenant", "acme")]).await,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, &[("x-tessera-tenant", "acme")]).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn demo_mode_accepts_tenant_header() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = app(state(keys, true));
    assert_eq!(
        call(&app, &[("x-tessera-tenant", "acme")]).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn created_key_authenticates_in_locked_mode() {
    let keys = Arc::new(MemoryApiKeyStore::new());

    // Create a key in demo mode.
    let demo = app(state(keys.clone(), true));
    let resp = demo
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("content-type", "application/json")
                .header("x-tessera-tenant", "acme")
                .body(Body::from(serde_json::json!({"name": "ci"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let key = value["key"].as_str().unwrap().to_string();
    assert!(key.starts_with("tsk_"));
    assert_eq!(value["record"]["tenant"], "acme");

    // The created key works against a locked (auth-required) broker.
    let locked = app(state(keys, false));
    let bearer = format!("Bearer {key}");
    assert_eq!(
        call(&locked, &[("authorization", &bearer)]).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn list_and_revoke_keys() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let (record, key) = keys
        .create("acme", "test", None, Default::default())
        .await
        .unwrap();
    let app = app(state(keys, false));
    let bearer = format!("Bearer {key}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/keys")
                .header("authorization", &bearer)
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
    assert_eq!(value["items"].as_array().unwrap().len(), 1);

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/keys/{}", record.id))
                .header("authorization", &bearer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_routes_are_rate_limited() {
    let keys = Arc::new(MemoryApiKeyStore::new());
    let app = tessera_broker::http::app(Arc::new(AppState {
        service: service(),
        keys,
        demo_allow: true,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: Some(2),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::default()),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }));

    let get = |path: &'static str| {
        app.clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
    };

    // /v1/verify/domain is public; the third call from the same client is throttled.
    assert_eq!(
        get("/v1/verify/domain").await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        get("/v1/verify/domain").await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        get("/v1/verify/domain").await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // /healthz is never throttled (probes).
    assert_eq!(get("/healthz").await.unwrap().status(), StatusCode::OK);
}
