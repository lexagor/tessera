//! Public-route rate limiting must key on a spoof-resistant client IP.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn app(public_per_minute: u32, trusted: Vec<String>) -> axum::Router {
    let service = Arc::new(tessera_broker::authorize::AuthorizeService {
        policies: Arc::new(tessera_broker::policy::InMemoryPolicyStore::new()),
        issuers: Arc::new(tessera_broker::issuers::IssuerRegistry::new()),
        authority_hmac_secret: None,
        authority_require_token: false,
        signer: Arc::new(
            tessera_broker::receipt::ReceiptSigner::from_hex_or_random(
                Some("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
                84532,
                "0x0000000000000000000000000000000000000000",
            )
            .unwrap(),
        ),
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
        retention_days: 0,
        anchor_confirmations: 0,
        anchor_reorg_grace_secs: 0,
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
        demo_policy: None,
    });
    tessera_broker::http::app(Arc::new(tessera_broker::AppState {
        service,
        keys: Arc::new(tessera_broker::MemoryApiKeyStore::new()),
        demo_allow: false,
        admin_token: None,
        rate_limit_per_min: None,
        public_rate_limit_per_min: Some(public_per_minute),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        trusted_proxies: Arc::new(tessera_broker::clientip::TrustedProxies::new(&trusted)),
        cache: Arc::new(tessera_broker::cache::MemoryCache::new()),
        chain_read_limit: 1_000,
        heavy_route_rate_limit: None,
    }))
}

async fn get(app: &axum::Router, forwarded_for: &str) -> StatusCode {
    let mut req = Request::builder()
        .uri("/v1/verify/domain")
        .header("x-forwarded-for", forwarded_for)
        .body(Body::empty())
        .unwrap();
    // `oneshot` bypasses the TCP stack, so supply the peer address the middleware reads.
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000,
        ))));
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn forwarded_for_is_ignored_from_untrusted_peers() {
    // No trusted proxies: the test client's own address is used, so rotating XFF must not
    // grant fresh budgets.
    let app = app(1, vec![]);
    assert_eq!(get(&app, "198.51.100.1").await, StatusCode::OK);
    assert_eq!(
        get(&app, "198.51.100.2").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn forwarded_for_is_honored_from_trusted_proxies() {
    // The test client connects from 127.0.0.1; trusting it makes XFF the client identity,
    // so distinct clients get independent budgets (and a single one still gets throttled).
    let app = app(1, vec!["127.0.0.1/32".into()]);
    assert_eq!(get(&app, "198.51.100.1").await, StatusCode::OK);
    assert_eq!(get(&app, "198.51.100.2").await, StatusCode::OK);
    assert_eq!(
        get(&app, "198.51.100.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}
