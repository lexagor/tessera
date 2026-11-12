//! HTTP surface for the broker.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::{set_header::SetResponseHeaderLayer, timeout::TimeoutLayer};

use crate::anchoring::AnchorTarget;
use crate::auth::{extract_key, ApiKeyStore, Tenant};

/// Per-key budget carried through the request (None = tenant budget only).
#[derive(Clone, Copy, Debug)]
pub struct ApiKeyBudget(pub Option<u32>);

/// Per-key least-privilege scope carried through the request.
#[derive(Clone, Debug, Default)]
pub struct ApiKeyScope(pub crate::auth::KeyScope);

/// The authenticated API key's id (used to scope idempotency keys).
#[derive(Clone, Debug)]
pub struct ApiKeyId(pub String);
use crate::authorize::{
    AuthorizeRequest, AuthorizeResponse, AuthorizeService, RecordRequest, RecordResponse,
    RevokeOutcome,
};
use crate::chain::ChainEntry;
use crate::error::BrokerError;
use crate::policy::Policy;
use crate::proxy::{ProxyRequest, ProxyResponse};
use crate::receipt::{Domain, GrantReceipt};
use crate::verify;

/// Shared application state for the HTTP layer.
pub struct AppState {
    pub service: Arc<AuthorizeService>,
    pub keys: Arc<dyn ApiKeyStore>,
    /// Accept `x-tessera-tenant` without a key (local dev/demo).
    pub demo_allow: bool,
    /// Authorizes API-key management (create/revoke).
    pub admin_token: Option<String>,
    /// Per-tenant request budget (requests/minute); None disables limiting.
    pub rate_limit_per_min: Option<u32>,
    /// Per-IP budget for public routes (verify/metrics); None disables limiting.
    pub public_rate_limit_per_min: Option<u32>,
    pub rate_limiter: Arc<dyn crate::ratelimit::RateLimiter>,
    /// Peers allowed to set `X-Forwarded-For` (empty = trust none).
    pub trusted_proxies: Arc<crate::clientip::TrustedProxies>,
    /// Cache used for `Idempotency-Key` replay (memory or Redis).
    pub cache: Arc<dyn crate::cache::Cache>,
    /// Default/maximum entries returned by `GET /v1/chain/:agent` when no limit is given.
    pub chain_read_limit: usize,
    /// Per-tenant budget for expensive evidence routes (`HEAVY_ROUTE_RATE_LIMIT_PER_MIN`).
    pub heavy_route_rate_limit: Option<u32>,
}

pub fn app(state: Arc<AppState>) -> Router {
    // Public, unauthenticated routes: verify + metrics, limited per client IP.
    let public = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/v1/verify/domain", get(verify_domain))
        .route("/v1/verify/receipt", post(verify_receipt_handler))
        .route("/v1/verify/chain", post(verify_chain_handler))
        .route("/v1/verify/merkle", post(verify_merkle_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            public_rate_limit,
        ));

    let protected = Router::new()
        .route("/v1/authorize", post(authorize_handler))
        .route("/v1/record", post(record_handler))
        .route("/v1/proxy", post(proxy_handler))
        .route("/v1/chain/:agent", get(chain_handler))
        .route("/v1/chain/:agent/anchor", get(anchor_handler))
        .route(
            "/v1/chain/:agent/proof",
            get(receipt_proof_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                heavy_route_limit,
            )),
        )
        .route(
            "/v1/chain/:agent/anchor/submit",
            post(submit_anchor_handler),
        )
        .route("/v1/anchors", get(list_anchors))
        .route("/v1/anchors/gaps", get(anchor_gaps_handler))
        .route("/v1/key-events", get(key_event_log))
        .route("/v1/key-templates", get(key_templates))
        .route("/v1/tools", get(list_tool_pins))
        .route(
            "/v1/tools/:tool",
            axum::routing::put(put_tool_pin).delete(delete_tool_pin),
        )
        .route("/v1/keys/lint", get(lint_keys).post(remediate_keys))
        .route(
            "/v1/remediation-policy",
            get(get_remediation_policy)
                .put(put_remediation_policy)
                .delete(delete_remediation_policy),
        )
        .route(
            "/v1/remediation-policy/preview",
            post(preview_remediation_policy),
        )
        .route("/v1/integrity", get(integrity_report))
        .route("/v1/alerts/ack", post(ack_alert))
        .route("/v1/alerts/acks", get(list_alert_acks))
        .route(
            "/v1/alert-config",
            get(get_alert_config)
                .put(put_alert_config)
                .delete(delete_alert_config),
        )
        .route(
            "/v1/export/chain/:agent",
            get(export_chain).route_layer(middleware::from_fn_with_state(
                state.clone(),
                heavy_route_limit,
            )),
        )
        .route(
            "/v1/export/tenant",
            get(export_tenant).route_layer(middleware::from_fn_with_state(
                state.clone(),
                heavy_route_limit,
            )),
        )
        .route(
            "/v1/import",
            // Bundles are much larger than ordinary requests: give this route its own cap
            // and its own budget.
            post(import_chain)
                .layer(DefaultBodyLimit::max(max_import_bytes()))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    heavy_route_limit,
                )),
        )
        .route(
            "/v1/export/tenant/archive",
            get(export_tenant_archive).route_layer(middleware::from_fn_with_state(
                state.clone(),
                heavy_route_limit,
            )),
        )
        .route("/v1/limits", get(effective_limits))
        .route("/v1/anchor-config/check", post(check_anchor_config))
        .route(
            "/v1/anchor-config",
            get(get_anchor_config).put(put_anchor_config),
        )
        .route("/v1/policies", get(list_policies))
        .route("/v1/policies/propose", get(propose_policy_handler))
        .route(
            "/v1/policies/:id",
            get(get_policy).put(put_policy).delete(delete_policy),
        )
        .route("/v1/keys", get(list_keys).post(create_key))
        .route("/v1/keys/:id", axum::routing::delete(revoke_key))
        .route("/v1/keys/:id/renew", post(renew_key))
        .route("/v1/keys/:id", axum::routing::patch(update_key))
        .route("/v1/revoke", post(revoke_handler))
        .route("/v1/transitions", post(transition_handler))
        .route("/v1/revocations", get(list_revocations))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(public)
        .merge(protected)
        // A panic in one handler returns 500 instead of tearing down the connection.
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        // Cap request bodies and bound request duration.
        .layer(DefaultBodyLimit::max(max_body_bytes()))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(request_timeout_secs()),
        ))
        // APIs return JSON/SECRET material; never let a browser sniff or cache it.
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

fn max_import_bytes() -> usize {
    std::env::var("MAX_IMPORT_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8 * 1024 * 1024)
}

fn max_body_bytes() -> usize {
    std::env::var("MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64 * 1024)
}

fn request_timeout_secs() -> u64 {
    std::env::var("REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// Budget for expensive evidence routes (export/import/proof/archive), requests/minute,
/// from `HEAVY_ROUTE_RATE_LIMIT_PER_MIN` (unset disables; the tenant budget still applies).
pub fn heavy_route_rate_limit() -> Option<u32> {
    std::env::var("HEAVY_ROUTE_RATE_LIMIT_PER_MIN")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
}

/// Enforce the heavy-route budget after authentication.
async fn heavy_route_limit(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(per_minute) = state.heavy_route_rate_limit {
        let key = format!("heavy:{tenant}");
        if !state.rate_limiter.allow_per_minute(&key, per_minute).await {
            crate::metrics::throttled();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate limit exceeded for evidence endpoints" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Rate limit for public routes, keyed by client IP (unauthenticated compute).
async fn public_rate_limit(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(per_minute) = state.public_rate_limit_per_min {
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());
        let forwarded = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok());
        let ip = match peer {
            Some(peer) => state.trusted_proxies.client_ip(peer, forwarded).to_string(),
            None => "unknown".to_string(),
        };
        let key = format!("public:{ip}");
        if !state.rate_limiter.allow_per_minute(&key, per_minute).await {
            crate::metrics::throttled();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate limit exceeded" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Auth middleware: resolve the tenant from an API key (or the demo header) and stash it.
async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    match resolve_tenant(&state, req.headers()).await {
        Ok(record) => {
            let tenant = match &record {
                Some(record) => record.tenant.clone(),
                None => req
                    .headers()
                    .get("x-tessera-tenant")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("default")
                    .to_string(),
            };

            // Per-key budget first: one integration must not exhaust the tenant.
            if let Some(per_minute) = record.as_ref().and_then(|r| r.rate_limit_per_min) {
                let key_id = record.as_ref().map(|r| r.id.as_str()).unwrap_or("demo");
                let bucket = format!("apikey:{tenant}:{key_id}");
                if !state
                    .rate_limiter
                    .allow_per_minute(&bucket, per_minute)
                    .await
                {
                    crate::metrics::throttled();
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({ "error": "rate limit exceeded for API key" })),
                    )
                        .into_response();
                }
            }

            if let Some(per_minute) = state.rate_limit_per_min {
                if !state
                    .rate_limiter
                    .allow_per_minute(&tenant, per_minute)
                    .await
                {
                    crate::metrics::throttled();
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({ "error": "rate limit exceeded for tenant" })),
                    )
                        .into_response();
                }
            }
            if let Some(record) = record {
                req.extensions_mut()
                    .insert(ApiKeyBudget(record.rate_limit_per_min));
                req.extensions_mut().insert(ApiKeyScope(record.scope));
                req.extensions_mut().insert(ApiKeyId(record.id));
            }
            req.extensions_mut().insert(Tenant(tenant));
            next.run(req).await
        }
        Err(message) => {
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
        }
    }
}

async fn resolve_tenant(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<crate::auth::ApiKeyRecord>, String> {
    if let Some(key) = extract_key(headers) {
        return match state.keys.authenticate(&key).await {
            Ok(Some(record)) => Ok(Some(record)),
            Ok(None) => Err("invalid API key".into()),
            Err(e) => Err(e.to_string()),
        };
    }
    if state.demo_allow {
        return Ok(None);
    }
    Err("missing API key".into())
}

fn keys_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    if state.demo_allow {
        return true;
    }
    match &state.admin_token {
        Some(token) => headers
            .get("x-tessera-admin")
            .and_then(|v| v.to_str().ok())
            .map(|v| crate::auth::ct_eq(v, token))
            .unwrap_or(false),
        None => false,
    }
}

async fn healthz() -> Json<Value> {
    Json(
        json!({ "status": "ok", "service": "tessera-broker", "version": env!("CARGO_PKG_VERSION") }),
    )
}

// ── Authorize / record / proxy ──────────────────────────────────────────────

/// Whether the caller's key may perform a capability (`authorize`, `proxy`, `record`, `read`).
fn capability_allowed(scope: &Option<Extension<ApiKeyScope>>, capability: &str) -> bool {
    match scope {
        Some(Extension(ApiKeyScope(scope))) => scope.allows_capability(capability),
        None => true,
    }
}

fn denied_capability(capability: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "API key is not scoped for this operation",
            "capability": capability,
        })),
    )
}

/// Whether the caller's key is allowed to touch a specific agent's data.
fn agent_allowed(scope: &Option<Extension<ApiKeyScope>>, agent: &str) -> bool {
    match scope {
        Some(Extension(ApiKeyScope(scope))) => scope.allows_agent(agent),
        None => true,
    }
}

fn denied_agent(agent: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "API key is not scoped for this agent",
            "agentId": agent,
        })),
    )
}

fn scope_allows(scope: &Option<Extension<ApiKeyScope>>, agent: &str, tool: &str) -> bool {
    let resource = crate::issuers::resource_from_tool(tool);
    match scope {
        Some(Extension(ApiKeyScope(scope))) => {
            scope.allows_agent(agent) && scope.allows_resource(&resource)
        }
        None => true,
    }
}

/// Items a scope change would add/remove per dimension.
fn scope_diff(before: &crate::auth::KeyScope, after: &crate::auth::KeyScope) -> serde_json::Value {
    let dimension = |before: &[String], after: &[String]| {
        json!({
            "remove": before
                .iter()
                .filter(|item| !after.iter().any(|candidate| candidate == *item))
                .collect::<Vec<_>>(),
            "add": after
                .iter()
                .filter(|item| !before.iter().any(|candidate| candidate == *item))
                .collect::<Vec<_>>(),
        })
    };
    json!({
        "resources": dimension(&before.resources, &after.resources),
        "agents": dimension(&before.agents, &after.agents),
        "capabilities": dimension(&before.capabilities, &after.capabilities),
        "proxyPaths": dimension(&before.proxy_paths, &after.proxy_paths),
    })
}

/// Apply the tenant's auto-remediation policy to a freshly created or widened key.
async fn apply_auto_remediation(
    state: &AppState,
    tenant: &str,
    record: crate::auth::ApiKeyRecord,
) -> crate::auth::ApiKeyRecord {
    let decision = match state.service.remediation_decision(tenant, &record).await {
        Ok(decision) => decision,
        Err(e) => {
            tracing::warn!(tenant = %tenant, "auto-remediation check failed: {e}");
            return record;
        }
    };
    let Some((template, reasons)) = decision else {
        return record;
    };
    match state
        .keys
        .update(tenant, &record.id, Some(template.scope.clone()), None, None)
        .await
    {
        Ok(crate::auth::MutateOutcome::Done(updated)) => {
            crate::metrics::auto_remediated();
            if let Err(e) = state
                .service
                .append_key_event(
                    tenant,
                    "key.auto-remediated",
                    &updated,
                    json!({
                        "template": template.name,
                        "reasons": reasons,
                        "before": {
                            "resources": record.scope.resources,
                            "agents": record.scope.agents,
                            "capabilities": record.scope.capabilities,
                            "proxyPaths": record.scope.proxy_paths,
                        },
                    }),
                )
                .await
            {
                tracing::warn!(tenant = %tenant, "auto-remediation ledger append failed: {e}");
            }
            tracing::warn!(
                tenant = %tenant,
                key = %updated.prefix,
                template = template.name,
                "key narrowed by auto-remediation"
            );
            emit_key_event(
                state,
                tenant,
                "key.auto-remediated",
                &updated,
                json!({ "template": template.name }),
            )
            .await;
            updated
        }
        Ok(_) => record,
        Err(e) => {
            tracing::warn!(tenant = %tenant, "auto-remediation update failed: {e}");
            record
        }
    }
}

/// Emit a key lifecycle event to the tenant's webhook (best-effort, never fails the call).
/// Record a tenant-settings change in the audit ledger (secrets redacted).
async fn audit_setting_change(
    state: &AppState,
    tenant: &str,
    setting: &str,
    action: &str,
    before: serde_json::Value,
    after: serde_json::Value,
) {
    if let Err(e) = state
        .service
        .append_ledger_event(
            tenant,
            "setting.changed",
            setting,
            "",
            "",
            json!({ "setting": setting, "action": action, "before": before, "after": after }),
        )
        .await
    {
        tracing::warn!(tenant = %tenant, setting, "settings audit append failed: {e}");
    }
}

async fn emit_key_event(
    state: &AppState,
    tenant: &str,
    action: &str,
    record: &crate::auth::ApiKeyRecord,
    extra: serde_json::Value,
) {
    let mut payload = json!({
        "tenant": tenant,
        "action": action,
        "keyId": record.id,
        "name": record.name,
        "prefix": record.prefix,
        "version": record.version,
        "at": chrono::Utc::now().to_rfc3339(),
    });
    if let (Some(object), Some(extra)) = (payload.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
    }
    match state
        .service
        .send_event(tenant, "key.lifecycle", payload)
        .await
    {
        Ok(delivery) if delivery.attempted => {
            // Record the attempt so an integration can prove what was sent.
            if let Err(e) = state
                .service
                .append_key_event(
                    tenant,
                    "webhook.delivery",
                    record,
                    json!({
                        "event": "key.lifecycle",
                        "action": action,
                        "delivered": delivery.delivered,
                        "status": delivery.status,
                    }),
                )
                .await
            {
                tracing::warn!(tenant = %tenant, "delivery receipt append failed: {e}");
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(tenant = %tenant, action, "key lifecycle event failed: {e}"),
    }
}

/// Parse a replay cursor: RFC 3339 (with `+`, space-decoded `+`, or `Z`), a bare
/// timestamp, or unix seconds. Tolerates the query-string form where `+` arrives as a space.
fn parse_cursor(raw: &str) -> Result<chrono::DateTime<chrono::Utc>, (StatusCode, Json<Value>)> {
    let cleaned = raw.trim().replace(' ', "+");
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&cleaned) {
        return Ok(parsed.with_timezone(&chrono::Utc));
    }
    if let Ok(seconds) = cleaned.parse::<i64>() {
        if let Some(parsed) = chrono::DateTime::from_timestamp(seconds, 0) {
            return Ok(parsed);
        }
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&cleaned, "%Y-%m-%dT%H:%M:%S") {
        return Ok(naive.and_utc());
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": format!("since must be RFC 3339: {raw}") })),
    ))
}

/// Parse an optional `If-Match: "v<n>"` header into a version.
fn if_match_version(headers: &HeaderMap) -> Result<Option<u32>, (StatusCode, Json<Value>)> {
    let Some(raw) = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .strip_prefix('v')
        .unwrap_or(trimmed)
        .parse::<u32>()
        .map(Some)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "If-Match must look like \"v3\"" })),
            )
        })
}

/// Resolve the caller's `Idempotency-Key` into a cache key scoped to tenant + API key.
fn idempotency_cache_key(
    headers: &HeaderMap,
    tenant: &str,
    key_id: Option<&Extension<ApiKeyId>>,
    endpoint: &str,
) -> Option<String> {
    let value = headers
        .get("idempotency-key")
        .and_then(|header| header.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let key_scope = key_id
        .map(|Extension(ApiKeyId(id))| id.as_str())
        .unwrap_or("demo");
    // Scoped per endpoint: one logical operation may use the same key for authorize and
    // record without the two calls colliding.
    Some(format!("idem:{endpoint}:{tenant}:{key_scope}:{value}"))
}

/// Cached idempotency entry: the request fingerprint plus the original response. Binding the
/// key to the request means reusing a key with a different body is rejected (409) instead of
/// silently replaying an unrelated response.
#[derive(serde::Serialize, serde::Deserialize)]
struct IdempotencyEntry {
    request_hash: String,
    response: serde_json::Value,
}

fn request_fingerprint<T: serde::Serialize>(request: &T) -> String {
    match serde_json::to_value(request) {
        Ok(value) => crate::canonical::hash_json(&value),
        Err(_) => String::new(),
    }
}

/// Replay a cached response for `cache_key` when the request fingerprint matches; run
/// `execute` and cache the result otherwise. A mismatched fingerprint is a 409.
async fn idempotent<T, F>(
    state: &AppState,
    cache_key: Option<String>,
    request_hash: String,
    execute: F,
) -> Result<T, (StatusCode, Json<Value>)>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    F: std::future::Future<Output = Result<T, (StatusCode, Json<Value>)>>,
{
    let Some(cache_key) = cache_key else {
        return execute.await;
    };
    if let Ok(Some(cached)) = state.cache.get(&cache_key).await {
        if let Ok(entry) = serde_json::from_str::<IdempotencyEntry>(&cached) {
            if entry.request_hash == request_hash {
                if let Ok(response) = serde_json::from_value::<T>(entry.response) {
                    return Ok(response);
                }
            } else {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "Idempotency-Key was already used with a different request",
                    })),
                ));
            }
        }
    }

    let response = execute.await?;
    if let (Ok(value), Ok(encoded)) = (
        serde_json::to_value(&response),
        serde_json::to_string(&IdempotencyEntry {
            request_hash,
            response: serde_json::to_value(&response).unwrap_or(serde_json::Value::Null),
        }),
    ) {
        let _ = value;
        let _ = state
            .cache
            .put(&cache_key, &encoded, idempotency_ttl_secs())
            .await;
    }
    Ok(response)
}

fn idempotency_ttl_secs() -> u64 {
    std::env::var("IDEMPOTENCY_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600)
}

async fn authorize_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    key_id: Option<Extension<ApiKeyId>>,
    headers: HeaderMap,
    Json(req): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "authorize") {
        return Err(denied_capability("authorize"));
    }
    if !scope_allows(&scope, &req.agent_id, &req.tool) {
        crate::metrics::authorize_deny();
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "API key is not scoped for this agent/resource",
                "resource": crate::issuers::resource_from_tool(&req.tool),
                "agentId": req.agent_id,
            })),
        ));
    }
    // Idempotent replay: a retried request with the same Idempotency-Key returns the original
    // response (and never issues a second credential or receipt).
    let cache_key = idempotency_cache_key(&headers, &tenant, key_id.as_ref(), "authorize");
    let request_hash = request_fingerprint(&req);
    let response = idempotent(&state, cache_key, request_hash, async {
        state
            .service
            .authorize(&tenant, req)
            .await
            .map_err(map_error)
    })
    .await?;
    Ok(Json(response))
}

async fn record_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    key_id: Option<Extension<ApiKeyId>>,
    headers: HeaderMap,
    Json(req): Json<RecordRequest>,
) -> Result<Json<RecordResponse>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "record") {
        return Err(denied_capability("record"));
    }
    if let Some(Extension(ApiKeyScope(scope))) = &scope {
        if !scope.allows_agent(&req.agent_id) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "API key is not scoped for this agent" })),
            ));
        }
    }

    // Idempotent replay: a retried outcome report returns the original response.
    let cache_key = idempotency_cache_key(&headers, &tenant, key_id.as_ref(), "record");
    let request_hash = request_fingerprint(&req);
    let response = idempotent(&state, cache_key, request_hash, async {
        state.service.record(&tenant, req).await.map_err(map_error)
    })
    .await?;
    Ok(Json(response))
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    key_id: Option<Extension<ApiKeyId>>,
    headers: HeaderMap,
    Json(req): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "proxy") {
        return Err(denied_capability("proxy"));
    }
    let cache_key = idempotency_cache_key(&headers, &tenant, key_id.as_ref(), "proxy");
    let request_hash = request_fingerprint(&req);
    let scope = scope.map(|Extension(ApiKeyScope(scope))| scope);
    let response = idempotent(&state, cache_key, request_hash, async {
        state
            .service
            .proxy_scoped(&tenant, req, scope.as_ref())
            .await
            .map_err(map_error)
    })
    .await?;
    Ok(Json(response))
}

// ── Chain / anchor ──────────────────────────────────────────────────────────

/// Default/maximum entries returned by the chain read endpoint (`CHAIN_READ_LIMIT`).
pub fn chain_read_limit() -> usize {
    std::env::var("CHAIN_READ_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1_000)
        .min(5_000)
}

#[derive(Debug, Deserialize, Default)]
struct ChainQuery {
    /// First chain index to return (0 = genesis). Omitted = the newest page.
    #[serde(default)]
    from: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn chain_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Path(agent): Path<String>,
    Query(query): Query<ChainQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    if !agent_allowed(&scope, &agent) {
        return Err(denied_agent(&agent));
    }
    // Bounded reads: a long chain must not be materialized in one response.
    let entries = state
        .service
        .chain_entries(&tenant, &agent)
        .await
        .map_err(map_error)?;
    let total = entries.len();
    let limit = query
        .limit
        .unwrap_or(state.chain_read_limit.max(1))
        .clamp(1, 5_000);
    let from = query
        .from
        .unwrap_or_else(|| total.saturating_sub(limit))
        .min(total);
    let end = (from + limit).min(total);
    let page: Vec<&crate::chain::ChainEntry> = entries[from..end].iter().collect();
    // Verification always covers the whole chain (a slice cannot be verified alone).
    let verified = state
        .service
        .verify_chain(&tenant, &agent)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({
        "agent": agent,
        "length": total,
        "from": from,
        "returned": page.len(),
        "hasMore": end < total,
        "nextFrom": if end < total { Some(end) } else { None },
        "verified": verified,
        "signer": state.service.signer.address_hex(),
        "entries": page,
    })))
}

#[derive(Debug, Deserialize)]
struct ReceiptProofQuery {
    /// Payload hash of the receipt to prove.
    #[serde(default)]
    receipt: Option<String>,
    /// Position in the chain (alternative to `receipt`).
    #[serde(default)]
    index: Option<usize>,
}

/// Prove a receipt is covered by an anchored Merkle root (optionally on-chain checked).
async fn receipt_proof_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Path(agent): Path<String>,
    Query(query): Query<ReceiptProofQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    if !agent_allowed(&scope, &agent) {
        return Err(denied_agent(&agent));
    }
    state
        .service
        .receipt_proof(&tenant, &agent, query.receipt.as_deref(), query.index)
        .await
        .map(Json)
        .map_err(map_error)
}

async fn anchor_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Path(agent): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    if !agent_allowed(&scope, &agent) {
        return Err(denied_agent(&agent));
    }
    let batch = state
        .service
        .anchor_batch(&tenant, &agent)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({
        "agent": agent,
        "tenant": tenant,
        "root": batch.root,
        "count": batch.count,
        "calldata": batch.calldata,
        "leaves": batch.leaves,
    })))
}

// ── Policies ────────────────────────────────────────────────────────────────

async fn list_policies(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let items = state
        .service
        .policies
        .list(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({ "items": items })))
}

async fn submit_anchor_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Path(agent): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Submitting an anchor spends gas and writes on-chain: a write operation.
    if !capability_allowed(&scope, "authorize") {
        return Err(denied_capability("authorize"));
    }
    if !agent_allowed(&scope, &agent) {
        return Err(denied_agent(&agent));
    }
    let record = state
        .service
        .submit_anchor(&tenant, &agent)
        .await
        .map_err(map_error)?;
    Ok(Json(json!(record)))
}

#[derive(Debug, Deserialize)]
struct LimitsQuery {
    /// When true, attach a broker-signed snapshot of the payload (evidence artifact).
    #[serde(default)]
    sign: bool,
}

/// Effective rate limits / TTL / retention for the calling tenant.
async fn effective_limits(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    budget: Option<Extension<ApiKeyBudget>>,
    scope: Option<Extension<ApiKeyScope>>,
    Query(query): Query<LimitsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut limits = state
        .service
        .effective_limits(&tenant)
        .await
        .map_err(map_error)?;
    if let Some(object) = limits.as_object_mut() {
        object.insert(
            "acceptedSigners".into(),
            json!(state.service.accepted_signers()),
        );
        object.insert(
            "tenantRateLimitPerMin".into(),
            json!(state.rate_limit_per_min),
        );
        object.insert(
            "publicRateLimitPerMin".into(),
            json!(state.public_rate_limit_per_min),
        );
        object.insert(
            "trustedProxiesConfigured".into(),
            json!(state.trusted_proxies.is_enabled()),
        );
        if let Some(Extension(ApiKeyBudget(limit))) = budget {
            object.insert("keyRateLimitPerMin".into(), json!(limit));
        }
        if let Some(Extension(ApiKeyScope(scope))) = &scope {
            object.insert(
                "keyScope".into(),
                json!({
                    "resources": scope.resources,
                    "agents": scope.agents,
                    "capabilities": scope.capabilities,
                }),
            );
            object.insert(
                "effectiveCapabilities".into(),
                json!(scope.effective_capabilities()),
            );
        } else {
            object.insert(
                "effectiveCapabilities".into(),
                json!(crate::auth::KEY_CAPABILITIES),
            );
        }
    }
    if query.sign {
        // The snapshot covers the payload *without* the snapshot field.
        let snapshot = crate::export::sign_payload(
            &state.service.signer,
            crate::export::LIMITS_DOMAIN,
            &limits,
        )
        .await
        .map_err(map_error)?;
        if let Some(object) = limits.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(snapshot).map_err(|e| {
                    map_error(BrokerError::Internal(format!("serialize snapshot: {e}")))
                })?,
            );
        }
    }
    Ok(Json(limits))
}

/// Tenant-wide export as a single downloadable tar.gz with a README for auditors.
async fn export_tenant_archive(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let bundle = state
        .service
        .export_tenant(&tenant)
        .await
        .map_err(map_error)?;
    let hint = "tessera-verify --archive . --expect-signer <address from this file>";
    let bytes = crate::export::build_tenant_archive(&bundle, hint).map_err(map_error)?;
    let filename = format!(
        "tessera-export-{}-{}.tar.gz",
        tenant.replace(
            |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
            "_"
        ),
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Debug, Deserialize, Default)]
struct ImportQuery {
    /// Compare the bundle against the local chain without importing anything.
    #[serde(default, rename = "dryRun")]
    dry_run: bool,
}

/// Import a signed export bundle into this broker (restore/replay path). `?dryRun=true`
/// reports drift without writing.
async fn import_chain(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Query(query): Query<ImportQuery>,
    Json(bundle): Json<crate::export::ExportBundle>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // An import rewrites/extends a tenant's chain from evidence: an administrative action.
    // Dry runs are read-only but still reveal the tenant's chain state.
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to import chain evidence" })),
        ));
    }
    let result = if query.dry_run {
        state.service.import_report(&tenant, &bundle).await
    } else {
        state.service.import_chain(&tenant, &bundle).await
    };
    result.map(Json).map_err(map_error)
}

/// Tenant-wide signed audit export (all agents + anchors).
async fn export_tenant(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let bundle = state
        .service
        .export_tenant(&tenant)
        .await
        .map_err(map_error)?;
    serde_json::to_value(bundle)
        .map(Json)
        .map_err(|e| map_error(BrokerError::Internal(format!("serialize export: {e}"))))
}

/// Signed audit export of an agent's chain (tenant-scoped).
#[derive(Debug, Deserialize, Default)]
struct ExportQuery {
    /// First chain index to export (0 = genesis).
    #[serde(default)]
    from: Option<u64>,
    /// Page size (default/max 5000).
    #[serde(default)]
    limit: Option<u64>,
}

async fn export_chain(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Path(agent): Path<String>,
    Query(query): Query<ExportQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    if !agent_allowed(&scope, &agent) {
        return Err(denied_agent(&agent));
    }
    let bundle = state
        .service
        .build_agent_export_page(&tenant, &agent, query.from, query.limit)
        .await
        .map_err(map_error)?;
    crate::metrics::export_bundle();
    serde_json::to_value(bundle)
        .map(Json)
        .map_err(|e| map_error(BrokerError::Internal(format!("serialize export: {e}"))))
}

/// Agents whose live chain has grown past their last live anchor.
async fn anchor_gaps_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let gaps = state
        .service
        .anchor_gaps(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({
        "threshold": state.service.anchor_gap_threshold,
        "items": gaps,
    })))
}

/// Probe the tenant's anchor configuration (RPC + contract) without submitting anything.
async fn check_anchor_config(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage tenant settings" })),
        ));
    }
    state
        .service
        .check_anchor_target(&tenant)
        .await
        .map(Json)
        .map_err(map_error)
}

/// Redacted alert target (never returns the token).
fn redact_alert_target(target: crate::alerts::AlertTarget) -> Value {
    json!({
        "url": target.url,
        "events": target.events,
        "hasToken": target.token.is_some(),
    })
}

async fn get_alert_config(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = keys_allowed(&state, &headers);
    if !admin && !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    // Read the stored target (token still encrypted): displaying `hasToken` must not depend
    // on decrypting, or rotating TENANT_SECRET_ENC_KEY would lock admins out of the config.
    let target = state
        .service
        .alert_router
        .target(&tenant)
        .await
        .map_err(map_error)?;
    // The webhook URL is a credential: only admins see the path/query in full.
    let target = match target {
        Some(target) if admin => Some(redact_alert_target(target)),
        Some(target) => Some(redact_alert_target_public(&target)),
        None => None,
    };
    Ok(Json(json!({
        "target": target,
        "globalFallback": state.service.alert_router.has_global(),
    })))
}

async fn put_alert_config(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(target): Json<crate::alerts::AlertTarget>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage tenant settings" })),
        ));
    }
    let before = state
        .service
        .alert_router
        .target(&tenant)
        .await
        .map_err(map_error)?
        .map(|target| redact_alert_target_public(&target))
        .unwrap_or(serde_json::Value::Null);
    let stored = state
        .service
        .set_alert_target(&tenant, target)
        .await
        .map_err(map_error)?;
    audit_setting_change(
        &state,
        &tenant,
        "alert",
        "set",
        before,
        redact_alert_target_public(&stored),
    )
    .await;
    Ok(Json(json!({
        "status": "ok",
        "target": redact_alert_target(stored),
    })))
}

async fn delete_alert_config(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage tenant settings" })),
        ));
    }
    let before = state
        .service
        .alert_router
        .target(&tenant)
        .await
        .map_err(map_error)?
        .map(|target| redact_alert_target_public(&target))
        .unwrap_or(serde_json::Value::Null);
    let removed = state
        .service
        .alert_router
        .delete_target(&tenant)
        .await
        .map_err(map_error)?;
    if removed {
        audit_setting_change(
            &state,
            &tenant,
            "alert",
            "deleted",
            before,
            serde_json::Value::Null,
        )
        .await;
    }
    Ok(Json(json!({ "deleted": removed })))
}

#[derive(Debug, Deserialize, Default)]
struct AnchorsQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn list_anchors(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Query(query): Query<AnchorsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let items = state
        .service
        .anchors
        .list(&tenant)
        .await
        .map_err(map_error)?;
    // Anchor records accumulate; return the newest page by default.
    let total = items.len();
    let limit = query.limit.unwrap_or(100).clamp(1, 1_000);
    let page: Vec<_> = items.into_iter().rev().take(limit).collect::<Vec<_>>();
    let page: Vec<_> = page.into_iter().rev().collect();
    Ok(Json(json!({
        "count": total,
        "returned": page.len(),
        "hasMore": page.len() < total,
        "items": page,
    })))
}

/// Tenant anchor config, with the private key redacted (never returned over the API).
fn redact_target(target: AnchorTarget) -> Value {
    json!({
        "chainId": target.chain_id,
        "rpcUrl": target.rpc_url,
        "contract": target.contract,
        "hasPrivateKey": target.private_key.is_some(),
        "signerHistory": target.signer_history,
    })
}

/// Host-only view of a URL (`host[:port]`), safe to show to read-only callers: paths and
/// query strings commonly embed provider keys or webhook secrets.
pub fn url_host(url: &str) -> String {
    match crate::netguard::host_of(url) {
        Ok((host, Some(port))) => format!("{host}:{port}"),
        Ok((host, None)) => host,
        Err(_) => "(invalid)".to_string(),
    }
}

/// Anchor configuration without the RPC path/query or any key material.
fn redact_target_public(target: &AnchorTarget) -> Value {
    json!({
        "chainId": target.chain_id,
        "rpcHost": url_host(&target.rpc_url),
        "contract": target.contract,
        "hasPrivateKey": target.private_key.is_some(),
        "signerHistory": target.signer_history,
    })
}

/// Alert configuration without the webhook path/query (where secrets usually live).
fn redact_alert_target_public(target: &crate::alerts::AlertTarget) -> Value {
    json!({
        "host": url_host(&target.url),
        "events": target.events,
        "hasToken": target.token.is_some(),
    })
}

async fn get_anchor_config(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = keys_allowed(&state, &headers);
    if !admin && !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let target = state
        .service
        .anchor_targets
        .get(&tenant)
        .await
        .map_err(map_error)?;
    match target {
        // Admins see the full URL; read-capable keys get a host-only summary (RPC paths
        // often embed provider API keys).
        Some(target) if admin => Ok(Json(json!({ "target": redact_target(target) }))),
        Some(target) => Ok(Json(json!({ "target": redact_target_public(&target) }))),
        None => Ok(Json(json!({ "target": null }))),
    }
}

async fn put_anchor_config(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(target): Json<AnchorTarget>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage tenant settings" })),
        ));
    }
    let before = state
        .service
        .anchor_targets
        .get(&tenant)
        .await
        .map_err(map_error)?
        .map(|target| redact_target_public(&target))
        .unwrap_or(serde_json::Value::Null);
    let stored = state
        .service
        .set_anchor_target(&tenant, target)
        .await
        .map_err(map_error)?;
    audit_setting_change(
        &state,
        &tenant,
        "anchor",
        "set",
        before,
        redact_target_public(&stored),
    )
    .await;
    Ok(Json(
        json!({ "status": "ok", "target": redact_target(stored) }),
    ))
}

/// Optional `METRICS_TOKEN`: when set, `/metrics` requires it as a bearer token.
fn metrics_token() -> Option<String> {
    std::env::var("METRICS_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
}

async fn metrics_handler(headers: HeaderMap) -> Response {
    if let Some(expected) = metrics_token() {
        let provided = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or("");
        if !crate::auth::ct_eq(provided, &expected) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "metrics token required" })),
            )
                .into_response();
        }
    }
    crate::metrics::render().into_response()
}

async fn propose_policy_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let proposal = state
        .service
        .propose_policy(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({
        "policy": proposal.policy,
        "evidence": proposal.evidence,
        "notes": proposal.notes,
    })))
}

async fn get_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match state
        .service
        .policies
        .get(&tenant, &id)
        .await
        .map_err(map_error)?
    {
        Some(policy) => Ok(Json(json!({ "policy": policy }))),
        None => Err(not_found(format!("policy '{id}' not found"))),
    }
}

/// Upper bound on stored policies per tenant: policy documents are tenant-supplied and the
/// store has no natural limit, so an integration could otherwise grow the database forever.
const MAX_POLICIES_PER_TENANT: usize = 100;

async fn put_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    Path(id): Path<String>,
    Json(mut policy): Json<Policy>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    policy.id = id;
    // Creating a new policy is capped; updating an existing one is always allowed.
    let existing = state
        .service
        .policies
        .list(&tenant)
        .await
        .map_err(map_error)?;
    if !existing.iter().any(|candidate| candidate.id == policy.id)
        && existing.len() >= MAX_POLICIES_PER_TENANT
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("policy limit reached ({MAX_POLICIES_PER_TENANT} per tenant)"),
            })),
        ));
    }
    state
        .service
        .policies
        .upsert(&tenant, policy.clone())
        .await
        .map_err(map_error)?;
    // Policies are the authorization core: record every change in the tamper-evident ledger.
    let digest = policy_digest(&policy);
    if let Err(e) = state
        .service
        .append_ledger_event(
            &tenant,
            "policy.changed",
            &policy.id,
            "",
            "",
            json!({
                "policyId": policy.id,
                "version": policy.version,
                "action": "set",
                "digest": digest,
            }),
        )
        .await
    {
        tracing::warn!(tenant = %tenant, "policy audit failed: {e}");
    }
    Ok(Json(
        json!({ "status": "ok", "policy": policy, "digest": digest }),
    ))
}

/// Canonical digest of a policy document (for audit entries).
fn policy_digest(policy: &Policy) -> String {
    serde_json::to_value(policy)
        .map(|value| crate::canonical::hash_json(&value))
        .unwrap_or_default()
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Capture the digest before deletion so the ledger records what was removed.
    let before = state
        .service
        .policies
        .get(&tenant, &id)
        .await
        .map_err(map_error)?;
    let digest_before = before.as_ref().map(policy_digest);
    let deleted = state
        .service
        .policies
        .delete(&tenant, &id)
        .await
        .map_err(map_error)?;
    if !deleted {
        return Err(not_found(format!("policy '{id}' not found")));
    }
    if let Err(e) = state
        .service
        .append_ledger_event(
            &tenant,
            "policy.changed",
            &id,
            "",
            "",
            json!({
                "policyId": id,
                "version": before.as_ref().map(|policy| policy.version),
                "action": "deleted",
                "digestBefore": digest_before,
            }),
        )
        .await
    {
        tracing::warn!(tenant = %tenant, "policy delete audit failed: {e}");
    }
    Ok(Json(json!({ "deleted": true })))
}

// ── API keys ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateKeyRequest {
    tenant: Option<String>,
    name: Option<String>,
    /// Optional per-key budget (requests/minute); falls back to the tenant budget.
    #[serde(rename = "rateLimitPerMin", default)]
    rate_limit_per_min: Option<u32>,
    /// Optional least-privilege scope: resource patterns (`stripe:*`).
    #[serde(rename = "allowedResources", default)]
    allowed_resources: Option<Vec<String>>,
    /// Optional least-privilege scope: agent ids this key may act as.
    #[serde(rename = "allowedAgents", default)]
    allowed_agents: Option<Vec<String>>,
    /// Optional capability list (`authorize`, `proxy`, `record`, `read`); empty = all.
    #[serde(rename = "allowedCapabilities", default)]
    allowed_capabilities: Option<Vec<String>>,
    /// Optional upstream path allowlist for proxied calls (`/v1/refunds*`).
    #[serde(rename = "allowedProxyPaths", default)]
    allowed_proxy_paths: Option<Vec<String>>,
    /// Optional named scope preset (see `GET /v1/key-templates`).
    #[serde(default)]
    template: Option<String>,
    /// Optional lifetime in seconds (converted to an explicit `expiresAt`).
    #[serde(rename = "ttlSeconds", default)]
    ttl_seconds: Option<u64>,
    /// Optional RFC 3339 expiry (mutually exclusive with `ttlSeconds`).
    #[serde(rename = "expiresAt", default)]
    expires_at: Option<String>,
}

async fn create_key(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(auth_tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let tenant = body.tenant.unwrap_or(auth_tenant);
    let name = body.name.unwrap_or_else(|| "default".to_string());
    let expires_at = match (body.ttl_seconds, body.expires_at.clone()) {
        (Some(ttl), _) => Some(
            (chrono::Utc::now() + chrono::Duration::seconds(ttl as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        (None, Some(raw)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(&raw).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("expiresAt must be RFC 3339: {e}") })),
                )
            })?;
            if parsed.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "expiresAt is in the past" })),
                ));
            }
            Some(
                parsed
                    .with_timezone(&chrono::Utc)
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
        }
        (None, None) => None,
    };
    let explicit_scope = body.allowed_resources.is_some()
        || body.allowed_agents.is_some()
        || body.allowed_capabilities.is_some()
        || body.allowed_proxy_paths.is_some();
    if body.template.is_some() && explicit_scope {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "provide either `template` or explicit scope fields, not both"
            })),
        ));
    }
    if let Some(template) = body.template.as_deref() {
        let resolved = crate::auth::key_template(template).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("unknown template '{template}'"),
                    "allowed": crate::auth::key_templates()
                        .into_iter()
                        .map(|template| template.name)
                        .collect::<Vec<_>>(),
                })),
            )
        })?;
        let (record, plaintext) = state
            .keys
            .create(
                &tenant,
                &name,
                None,
                crate::auth::NewKeyOptions {
                    // An explicit budget wins; otherwise the template's default applies so a
                    // preset key is never unbounded.
                    rate_limit_per_min: body
                        .rate_limit_per_min
                        .or(resolved.default_rate_limit_per_min),
                    scope: resolved.scope.clone(),
                    expires_at,
                },
            )
            .await
            .map_err(map_error)?;
        if let Err(e) = state
            .service
            .append_key_event(
                &tenant,
                "key.created",
                &record,
                json!({
                    "transitionType": "authority.granted",
                    "template": template,
                    "scope": record.scope,
                    "rateLimitPerMin": record.rate_limit_per_min,
                    "expiresAt": record.expires_at,
                }),
            )
            .await
        {
            tracing::warn!(tenant = %tenant, "key event ledger append failed: {e}");
        }
        let record = apply_auto_remediation(&state, &tenant, record).await;
        emit_key_event(
            &state,
            &tenant,
            "key.created",
            &record,
            json!({ "template": template }),
        )
        .await;
        return Ok(Json(json!({
            "key": plaintext,
            "record": record,
            "etag": crate::auth::key_etag(&record),
            "notice": "store this key now; it will not be shown again",
        })));
    }

    let capabilities = body.allowed_capabilities.clone().unwrap_or_default();
    for capability in &capabilities {
        if !crate::auth::KEY_CAPABILITIES
            .iter()
            .any(|known| known.eq_ignore_ascii_case(capability.trim()))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("unknown capability '{capability}'"),
                    "allowed": crate::auth::KEY_CAPABILITIES,
                })),
            ));
        }
    }
    let scope = crate::auth::KeyScope {
        resources: body.allowed_resources.clone().unwrap_or_default(),
        agents: body.allowed_agents.clone().unwrap_or_default(),
        capabilities: capabilities
            .iter()
            .map(|capability| capability.trim().to_ascii_lowercase())
            .collect(),
        proxy_paths: body.allowed_proxy_paths.clone().unwrap_or_default(),
    };
    let invalid = crate::auth::invalid_scope_patterns(&scope);
    if !invalid.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid scope patterns",
                "invalid": invalid,
                "hint": "resources must be exact, '*', or provider-scoped like 'stripe:*'; proxy paths must be absolute like '/v1/refunds*'",
            })),
        ));
    }
    let (record, plaintext) = state
        .keys
        .create(
            &tenant,
            &name,
            None,
            crate::auth::NewKeyOptions {
                rate_limit_per_min: body.rate_limit_per_min,
                scope,
                expires_at,
            },
        )
        .await
        .map_err(map_error)?;
    if let Err(e) = state
        .service
        .append_key_event(
            &tenant,
            "key.created",
            &record,
            json!({
                "transitionType": "authority.granted",
                "rateLimitPerMin": record.rate_limit_per_min,
                "expiresAt": record.expires_at,
                "scope": record.scope,
            }),
        )
        .await
    {
        tracing::warn!(tenant = %tenant, "key event ledger append failed: {e}");
    }
    let record = apply_auto_remediation(&state, &tenant, record).await;
    emit_key_event(&state, &tenant, "key.created", &record, json!({})).await;
    Ok(Json(json!({
        "key": plaintext,
        "record": record,
        "etag": crate::auth::key_etag(&record),
        "notice": "store this key now; it will not be shown again",
    })))
}

async fn list_keys(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let items = state.keys.list(&tenant).await.map_err(map_error)?;
    Ok(Json(json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
struct AckAlertRequest {
    event: String,
    #[serde(rename = "dedupKey")]
    dedup_key: String,
    /// Severity being acknowledged; defaults to the current severity when known.
    #[serde(default)]
    value: Option<u64>,
}

/// Acknowledge an alert condition so repeats stay quiet until it worsens.
async fn ack_alert(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    Json(body): Json<AckAlertRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let value = match body.value {
        Some(value) => value,
        None => state
            .service
            .current_condition_value(&tenant, &body.event, &body.dedup_key)
            .await
            .map_err(map_error)?
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "value is required for this event" })),
                )
            })?,
    };
    let ack = state
        .service
        .ack_alert(&tenant, &body.event, &body.dedup_key, value)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({ "status": "ok", "ack": ack })))
}

/// One view of the caller's integrity posture (chains, anchors, ledger, checkpoints, keys).
async fn integrity_report(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Query(query): Query<LimitsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let mut report = state
        .service
        .integrity_report(&tenant)
        .await
        .map_err(map_error)?;

    // Key posture comes from the key store (AppState), not the service.
    let records = state.keys.list(&tenant).await.map_err(map_error)?;
    let posture = crate::auth::key_posture(
        &records,
        chrono::Utc::now(),
        state.service.key_expiry_alert_days,
        state.service.key_rotation_max_age_hours,
    );
    if let Some(object) = report.as_object_mut() {
        object.insert("keys".into(), posture);
    }
    if query.sign {
        let snapshot = crate::export::sign_payload(
            &state.service.signer,
            crate::export::INTEGRITY_DOMAIN,
            &report,
        )
        .await
        .map_err(map_error)?;
        if let Some(object) = report.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(snapshot).map_err(|e| {
                    map_error(BrokerError::Internal(format!("serialize snapshot: {e}")))
                })?,
            );
        }
    }
    Ok(Json(report))
}

async fn list_alert_acks(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let acks = state
        .service
        .alert_acks
        .list(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({ "items": acks })))
}

#[derive(Debug, Deserialize, Default)]
struct UpdateKeyRequest {
    #[serde(rename = "allowedResources", default)]
    allowed_resources: Option<Vec<String>>,
    #[serde(rename = "allowedAgents", default)]
    allowed_agents: Option<Vec<String>>,
    #[serde(rename = "allowedCapabilities", default)]
    allowed_capabilities: Option<Vec<String>>,
    /// Optional upstream path allowlist for proxied calls.
    #[serde(rename = "allowedProxyPaths", default)]
    allowed_proxy_paths: Option<Vec<String>>,
    /// Send `null` to clear the per-key budget, a number to set it, omit to keep it.
    #[serde(rename = "rateLimitPerMin", default)]
    rate_limit_per_min: Option<Option<u32>>,
}

/// Update a key's scope/budget in place, recording the change in the audit ledger.
async fn update_key(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateKeyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let before = match state
        .keys
        .list(&tenant)
        .await
        .map_err(map_error)?
        .into_iter()
        .find(|record| record.id == id)
    {
        Some(record) if record.revoked_at.is_none() => record,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "key not found or revoked" })),
            ))
        }
    };

    // A scope update is a full replacement (omitted fields become empty).
    let scope_requested = body.allowed_resources.is_some()
        || body.allowed_agents.is_some()
        || body.allowed_capabilities.is_some()
        || body.allowed_proxy_paths.is_some();
    let scope = if scope_requested {
        let capabilities = body.allowed_capabilities.clone().unwrap_or_default();
        for capability in &capabilities {
            if !crate::auth::KEY_CAPABILITIES
                .iter()
                .any(|known| known.eq_ignore_ascii_case(capability.trim()))
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!("unknown capability '{capability}'"),
                        "allowed": crate::auth::KEY_CAPABILITIES,
                    })),
                ));
            }
        }
        Some(crate::auth::KeyScope {
            resources: body.allowed_resources.clone().unwrap_or_default(),
            agents: body.allowed_agents.clone().unwrap_or_default(),
            capabilities: capabilities
                .iter()
                .map(|capability| capability.trim().to_ascii_lowercase())
                .collect(),
            proxy_paths: body.allowed_proxy_paths.clone().unwrap_or_default(),
        })
    } else {
        None
    };

    // Optimistic concurrency: parse `If-Match` here, but let the store enforce it inside
    // its conditional update so a concurrent writer cannot slip between this read and the
    // write (check-then-act would be racy).
    let expected_version = match headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
    {
        Some(raw) => {
            let trimmed = raw.trim().trim_matches('"');
            Some(
                trimmed
                    .strip_prefix('v')
                    .unwrap_or(trimmed)
                    .parse::<u32>()
                    .map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({ "error": "If-Match must look like \"v3\"" })),
                        )
                    })?,
            )
        }
        None => None,
    };

    if let Some(scope) = &scope {
        let invalid = crate::auth::invalid_scope_patterns(scope);
        if !invalid.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid scope patterns",
                    "invalid": invalid,
                    "hint": "resources must be exact, '*', or provider-scoped like 'stripe:*'; proxy paths must be absolute like '/v1/refunds*'",
                })),
            ));
        }
    }
    let updated = match state
        .keys
        .update(
            &tenant,
            &id,
            scope,
            body.rate_limit_per_min,
            expected_version,
        )
        .await
        .map_err(map_error)?
    {
        crate::auth::MutateOutcome::Done(record) => record,
        crate::auth::MutateOutcome::NotFound => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "key not found or revoked" })),
            ));
        }
        crate::auth::MutateOutcome::Conflict { current } => {
            return Err((
                StatusCode::PRECONDITION_FAILED,
                Json(json!({
                    "error": "key was modified since the provided ETag",
                    "current": current,
                })),
            ));
        }
    };

    let updated = apply_auto_remediation(&state, &tenant, updated).await;
    if updated.scope != before.scope {
        if let Err(e) = state
            .service
            .append_key_event(
                &tenant,
                "key.scope-changed",
                &updated,
                json!({
                    "transitionType": if crate::auth::scope_exceeds(&before.scope, &updated.scope).is_empty() {
                        "authority.narrowed"
                    } else if crate::auth::scope_exceeds(&updated.scope, &before.scope).is_empty() {
                        "authority.widened"
                    } else {
                        "authority.changed"
                    },
                    "before": {
                        "resources": before.scope.resources,
                        "agents": before.scope.agents,
                        "capabilities": before.scope.capabilities,
                    },
                    "after": {
                        "resources": updated.scope.resources,
                        "agents": updated.scope.agents,
                        "capabilities": updated.scope.capabilities,
                    },
                }),
            )
            .await
        {
            tracing::warn!(tenant = %tenant, "key event ledger append failed: {e}");
        }
        emit_key_event(&state, &tenant, "key.scope-changed", &updated, json!({})).await;
    }
    if updated.rate_limit_per_min != before.rate_limit_per_min {
        if let Err(e) = state
            .service
            .append_key_event(
                &tenant,
                "key.budget-changed",
                &updated,
                json!({
                    "before": before.rate_limit_per_min,
                    "after": updated.rate_limit_per_min,
                }),
            )
            .await
        {
            tracing::warn!(tenant = %tenant, "key event ledger append failed: {e}");
        }
    }

    Ok(Json(json!({
        "status": "ok",
        "record": updated,
        "etag": crate::auth::key_etag(&updated),
    })))
}

/// Rotate a key's secret in place: same id, scope, budget and audit trail.
async fn renew_key(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(auth_tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RenewKeyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let expires_at = match (body.ttl_seconds, body.expires_at) {
        (Some(ttl), _) => Some(
            (chrono::Utc::now() + chrono::Duration::seconds(ttl as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        (None, Some(raw)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(&raw).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("expiresAt must be RFC 3339: {e}") })),
                )
            })?;
            if parsed.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "expiresAt is in the past" })),
                ));
            }
            Some(
                parsed
                    .with_timezone(&chrono::Utc)
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
        }
        (None, None) => None,
    };

    let expected_version = if_match_version(&headers)?;
    match state
        .keys
        .renew(&auth_tenant, &id, expires_at, expected_version)
        .await
        .map_err(map_error)?
    {
        crate::auth::MutateOutcome::Done((record, plaintext)) => {
            if let Err(e) = state
                .service
                .append_key_event(
                    &auth_tenant,
                    "key.renewed",
                    &record,
                    json!({
                        "transitionType": "authority.rotated",
                        "rotationCount": record.rotation_count,
                        "expiresAt": record.expires_at,
                    }),
                )
                .await
            {
                tracing::warn!(tenant = %auth_tenant, "key event ledger append failed: {e}");
            }
            emit_key_event(&state, &auth_tenant, "key.renewed", &record, json!({})).await;
            Ok(Json(json!({
                "key": plaintext,
                "record": record,
                "etag": crate::auth::key_etag(&record),
                "notice": "store this key now; it will not be shown again; the previous secret is invalid",
            })))
        }
        crate::auth::MutateOutcome::NotFound => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "key not found or revoked" })),
        )),
        crate::auth::MutateOutcome::Conflict { current } => Err((
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "key was modified since the provided ETag",
                "current": current,
            })),
        )),
    }
}

#[derive(Debug, Deserialize, Default)]
struct RenewKeyRequest {
    #[serde(rename = "ttlSeconds", default)]
    ttl_seconds: Option<u64>,
    #[serde(rename = "expiresAt", default)]
    expires_at: Option<String>,
}

async fn revoke_key(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let expected_version = if_match_version(&headers)?;
    match state
        .keys
        .revoke(&tenant, &id, expected_version)
        .await
        .map_err(map_error)?
    {
        crate::auth::MutateOutcome::Done(()) => {}
        crate::auth::MutateOutcome::NotFound => {
            return Err(not_found(format!("key '{id}' not found")));
        }
        crate::auth::MutateOutcome::Conflict { current } => {
            return Err((
                StatusCode::PRECONDITION_FAILED,
                Json(json!({
                    "error": "key was modified since the provided ETag",
                    "current": current,
                })),
            ));
        }
    }
    // Record the revocation against the key's last known metadata.
    if let Ok(records) = state.keys.list(&tenant).await {
        if let Some(record) = records.iter().find(|record| record.id == id) {
            if let Err(e) = state
                .service
                .append_key_event(
                    &tenant,
                    "key.revoked",
                    record,
                    json!({ "transitionType": "authority.revoked" }),
                )
                .await
            {
                tracing::warn!(tenant = %tenant, "key event ledger append failed: {e}");
            }
            emit_key_event(&state, &tenant, "key.revoked", record, json!({})).await;
        }
    }
    Ok(Json(json!({ "revoked": true })))
}

#[derive(Debug, Deserialize)]
struct LintQuery {
    template: String,
}

/// Report keys whose scope exceeds a named template (an over-grant audit).
async fn lint_keys(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Query(query): Query<LintQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let template = crate::auth::key_template(&query.template)
        .map(|template| template.scope)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("unknown template '{}'", query.template),
                    "allowed": crate::auth::key_templates()
                        .into_iter()
                        .map(|template| template.name)
                        .collect::<Vec<_>>(),
                })),
            )
        })?;

    let now = chrono::Utc::now();
    let mut exceeding = Vec::new();
    let mut compliant = 0usize;
    for record in state.keys.list(&tenant).await.map_err(map_error)? {
        if !crate::auth::record_is_live(&record, now) {
            continue;
        }
        let reasons = crate::auth::scope_exceeds(&record.scope, &template);
        if reasons.is_empty() {
            compliant += 1;
        } else {
            exceeding.push(json!({
                "keyId": record.id,
                "name": record.name,
                "prefix": record.prefix,
                "reasons": reasons,
            }));
        }
    }
    Ok(Json(json!({
        "tenant": tenant,
        "template": query.template,
        "compliant": compliant,
        "exceeding": exceeding,
        "compliantCount": compliant,
        "exceedingCount": exceeding.len(),
    })))
}

#[derive(Debug, Deserialize)]
struct RemediateRequest {
    template: String,
    /// Must be `true` for the narrowing to be applied (dry runs are the GET form).
    #[serde(default)]
    apply: bool,
}

/// Narrow every over-granted key to a template's scope. Recorded per key in the ledger.
async fn remediate_keys(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(body): Json<RemediateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let template = crate::auth::key_template(&body.template).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("unknown template '{}'", body.template),
                "allowed": crate::auth::key_templates()
                    .into_iter()
                    .map(|template| template.name)
                    .collect::<Vec<_>>(),
            })),
        )
    })?;

    let now = chrono::Utc::now();
    let mut remediated = Vec::new();
    let mut skipped = Vec::new();
    let mut compliant = 0usize;

    for record in state.keys.list(&tenant).await.map_err(map_error)? {
        if !crate::auth::record_is_live(&record, now) {
            continue;
        }
        let reasons = crate::auth::scope_exceeds(&record.scope, &template.scope);
        if reasons.is_empty() {
            compliant += 1;
            continue;
        }
        if !body.apply {
            // Preview the exact narrowing that applying would perform.
            let diff = scope_diff(&record.scope, &template.scope);
            skipped.push(json!({
                "keyId": record.id,
                "name": record.name,
                "reasons": reasons,
                "before": record.scope,
                "after": template.scope,
                "diff": diff,
            }));
            continue;
        }

        // Conditional update: never clobber a concurrent edit.
        let updated = state
            .keys
            .update(
                &tenant,
                &record.id,
                Some(template.scope.clone()),
                None,
                Some(record.version),
            )
            .await
            .map_err(map_error)?;
        match updated {
            crate::auth::MutateOutcome::Done(updated) => {
                if let Err(e) = state
                    .service
                    .append_key_event(
                        &tenant,
                        "key.scope-remediated",
                        &updated,
                        json!({
                            "transitionType": "authority.narrowed",
                            "template": template.name,
                            "reasons": reasons,
                            "before": {
                                "resources": record.scope.resources,
                                "agents": record.scope.agents,
                                "capabilities": record.scope.capabilities,
                                "proxyPaths": record.scope.proxy_paths,
                            },
                            "after": {
                                "resources": updated.scope.resources,
                                "agents": updated.scope.agents,
                                "capabilities": updated.scope.capabilities,
                                "proxyPaths": updated.scope.proxy_paths,
                            },
                        }),
                    )
                    .await
                {
                    tracing::warn!(tenant = %tenant, "key event ledger append failed: {e}");
                }
                remediated.push(json!({
                    "keyId": updated.id,
                    "name": updated.name,
                    "reasons": reasons,
                }));
            }
            _ => skipped.push(json!({
                "keyId": record.id,
                "name": record.name,
                "reasons": reasons,
                "skipped": "key changed concurrently",
            })),
        }
    }

    Ok(Json(json!({
        "tenant": tenant,
        "template": body.template,
        "applied": body.apply,
        "compliant": compliant,
        "remediated": remediated,
        "skipped": skipped,
        "remediatedCount": remediated.len(),
        "skippedCount": skipped.len(),
    })))
}

#[derive(Debug, Deserialize)]
struct PreviewRemediationPolicy {
    template: String,
}

/// Show exactly what enabling a policy would narrow, without storing or applying anything.
async fn preview_remediation_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(body): Json<PreviewRemediationPolicy>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let template = crate::auth::key_template(&body.template).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("unknown template '{}'", body.template),
                "allowed": crate::auth::key_templates()
                    .into_iter()
                    .map(|template| template.name)
                    .collect::<Vec<_>>(),
            })),
        )
    })?;

    let now = chrono::Utc::now();
    let mut would_narrow = Vec::new();
    let mut compliant = 0usize;
    for record in state.keys.list(&tenant).await.map_err(map_error)? {
        if !crate::auth::record_is_live(&record, now) {
            continue;
        }
        let reasons = crate::auth::scope_exceeds(&record.scope, &template.scope);
        if reasons.is_empty() {
            compliant += 1;
            continue;
        }
        would_narrow.push(json!({
            "keyId": record.id,
            "name": record.name,
            "prefix": record.prefix,
            "reasons": reasons,
            "before": record.scope,
            "after": template.scope,
            "diff": scope_diff(&record.scope, &template.scope),
        }));
    }

    let current = state
        .service
        .remediation_policies
        .get(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({
        "tenant": tenant,
        "template": template.name,
        "templateVersion": template.version,
        "currentPolicy": current,
        "wouldNarrow": would_narrow,
        "wouldNarrowCount": would_narrow.len(),
        "compliantCount": compliant,
        "previewedAt": now.to_rfc3339(),
    })))
}

/// Current auto-remediation policy for the tenant.
async fn get_remediation_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) && !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let policy = state
        .service
        .remediation_policies
        .get(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({ "policy": policy })))
}

#[derive(Debug, Deserialize)]
struct PutRemediationPolicy {
    template: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

async fn put_remediation_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(body): Json<PutRemediationPolicy>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    if crate::auth::key_template(&body.template).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("unknown template '{}'", body.template),
                "allowed": crate::auth::key_templates()
                    .into_iter()
                    .map(|template| template.name)
                    .collect::<Vec<_>>(),
            })),
        ));
    }
    let template = crate::auth::key_template(&body.template).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "unknown template" })),
        )
    })?;
    let policy = crate::remediation::RemediationPolicy {
        template: template.name.to_string(),
        template_version: Some(template.version),
        enabled: body.enabled,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    let before = state
        .service
        .remediation_policies
        .get(&tenant)
        .await
        .map_err(map_error)?
        .map(|policy| json!(policy))
        .unwrap_or(serde_json::Value::Null);
    state
        .service
        .remediation_policies
        .set(&tenant, policy.clone())
        .await
        .map_err(map_error)?;
    audit_setting_change(
        &state,
        &tenant,
        "remediation",
        "set",
        before,
        json!(policy.clone()),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "policy": policy })))
}

async fn delete_remediation_policy(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to manage keys" })),
        ));
    }
    let before = state
        .service
        .remediation_policies
        .get(&tenant)
        .await
        .map_err(map_error)?
        .map(|policy| json!(policy))
        .unwrap_or(serde_json::Value::Null);
    let removed = state
        .service
        .remediation_policies
        .delete(&tenant)
        .await
        .map_err(map_error)?;
    if removed {
        audit_setting_change(
            &state,
            &tenant,
            "remediation",
            "deleted",
            before,
            serde_json::Value::Null,
        )
        .await;
    }
    Ok(Json(json!({ "deleted": removed })))
}

#[derive(Debug, Deserialize)]
struct PutToolPin {
    /// The complete tool definition the client was given (name, description, schemas,
    /// annotations).
    definition: serde_json::Value,
}

/// Approve (pin) a tool definition. Re-pinning accepts a changed definition after review.
async fn put_tool_pin(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Path(tool): Path<String>,
    Json(body): Json<PutToolPin>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to approve tools" })),
        ));
    }
    if !crate::tool_pins::valid_tool_name(&tool) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid tool name: use 1-256 characters of [A-Za-z0-9._:@-]",
            })),
        ));
    }
    if !body.definition.is_object() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "definition must be a JSON object" })),
        ));
    }
    let definition_hash = crate::tool_pins::definition_hash(&body.definition);
    let now = chrono::Utc::now().to_rfc3339();
    let pin = crate::tool_pins::ToolPin {
        tenant: tenant.clone(),
        tool: tool.clone(),
        definition_hash: definition_hash.clone(),
        definition: body.definition,
        created_at: now.clone(),
        updated_at: now,
    };
    state
        .service
        .tool_pins
        .set(pin.clone())
        .await
        .map_err(map_error)?;
    if let Err(e) = state
        .service
        .append_ledger_event(
            &tenant,
            "tool.pinned",
            &tool,
            "",
            "",
            json!({ "tool": tool, "definitionHash": definition_hash }),
        )
        .await
    {
        tracing::warn!(tenant = %tenant, "tool pin audit failed: {e}");
    }
    Ok(Json(json!({ "status": "ok", "pin": pin })))
}

/// List approved tool pins (read capability).
async fn list_tool_pins(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let items = state
        .service
        .tool_pins
        .list(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({ "count": items.len(), "items": items })))
}

/// Remove a pin (returns the tool to unpinned behaviour).
async fn delete_tool_pin(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Path(tool): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to approve tools" })),
        ));
    }
    let removed = state
        .service
        .tool_pins
        .delete(&tenant, &tool)
        .await
        .map_err(map_error)?;
    if removed {
        if let Err(e) = state
            .service
            .append_ledger_event(
                &tenant,
                "tool.unpinned",
                &tool,
                "",
                "",
                json!({ "tool": tool }),
            )
            .await
        {
            tracing::warn!(tenant = %tenant, "tool unpin audit failed: {e}");
        }
    }
    Ok(Json(json!({ "deleted": removed })))
}

/// Available key scope presets.
async fn key_templates() -> Json<Value> {
    let templates: Vec<Value> = crate::auth::key_templates()
        .into_iter()
        .map(|template| {
            json!({
                "name": template.name,
                "version": template.version,
                "description": template.description,
                "defaultRateLimitPerMin": template.default_rate_limit_per_min,
                "scope": template.scope,
            })
        })
        .collect();
    Json(json!({ "templates": templates }))
}

/// A tenant's key-event ledger (hash-linked, signed), with a verification verdict.
#[derive(Debug, Deserialize, Default)]
struct KeyEventQuery {
    /// RFC 3339 cursor: replay events strictly after this timestamp.
    #[serde(default)]
    since: Option<String>,
    /// Page size (default 500, max 5000).
    #[serde(default)]
    limit: Option<usize>,
}

async fn key_event_log(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
    Query(query): Query<KeyEventQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let since = match query.since.as_deref() {
        Some(raw) => Some(parse_cursor(raw)?),
        None => None,
    };
    state
        .service
        .key_event_log(&tenant, since, query.limit)
        .await
        .map(Json)
        .map_err(map_error)
}

// ── Revocation ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeRequest {
    target: String,
    kind: Option<String>,
    reason: Option<String>,
}

async fn revoke_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<RevokeOutcome>, (StatusCode, Json<Value>)> {
    // Killing an agent or grant is an emergency control action: admin only.
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to revoke agents or grants" })),
        ));
    }
    let kind = body.kind.unwrap_or_else(|| "grant".to_string());
    state
        .service
        .revoke(&tenant, &body.target, &kind, body.reason)
        .await
        .map(Json)
        .map_err(map_error)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransitionRequest {
    #[serde(rename = "type")]
    kind: String,
    target: String,
    reason: Option<String>,
    #[serde(default)]
    details: serde_json::Value,
}

async fn transition_handler(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    headers: HeaderMap,
    Json(body): Json<TransitionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !keys_allowed(&state, &headers) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "not authorized to record authority transitions" })),
        ));
    }
    if !matches!(
        body.kind.as_str(),
        "authority.stepped_up"
            | "authority.narrowed"
            | "authority.granted"
            | "authority.delegated"
            | "authority.changed"
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "unsupported authority transition type" })),
        ));
    }
    let mut details = if body.details.is_object() {
        body.details
    } else {
        json!({})
    };
    if let Some(object) = details.as_object_mut() {
        object.insert("transitionType".into(), json!(body.kind));
        object.insert("target".into(), json!(body.target));
        if let Some(reason) = body.reason {
            object.insert("reason".into(), json!(reason));
        }
    }
    let event = state
        .service
        .append_ledger_event(&tenant, &body.kind, &body.target, &body.target, "", details)
        .await
        .map_err(map_error)?;
    Ok(Json(json!(event)))
}

async fn list_revocations(
    State(state): State<Arc<AppState>>,
    Extension(Tenant(tenant)): Extension<Tenant>,
    scope: Option<Extension<ApiKeyScope>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !capability_allowed(&scope, "read") {
        return Err(denied_capability("read"));
    }
    let items = state
        .service
        .revocations
        .list(&tenant)
        .await
        .map_err(map_error)?;
    Ok(Json(json!({ "items": items })))
}

// ── Verification (public: no API key required) ──────────────────────────────

fn domain_for(
    state: &AppState,
    chain_id: Option<u64>,
    verifying_contract: Option<String>,
) -> Result<Domain, BrokerError> {
    let base = state.service.signer.domain();
    let id = chain_id.unwrap_or(base.chain_id);
    let contract = verifying_contract.unwrap_or_else(|| base.contract_hex());
    Domain::new(id, &contract)
}

async fn verify_domain(State(state): State<Arc<AppState>>) -> Json<Value> {
    let domain = state.service.signer.domain();
    Json(json!({
        "chainId": domain.chain_id,
        "verifyingContract": domain.contract_hex(),
        "domainVersion": domain.version,
        "supportedDomainVersions": ["1", "2"],
        "signer": state.service.signer.address_hex(),
        "signers": state.service.accepted_signers(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyReceiptRequest {
    expected_signer: Option<String>,
    chain_id: Option<u64>,
    verifying_contract: Option<String>,
    #[serde(flatten)]
    receipt: GrantReceipt,
}

async fn verify_receipt_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VerifyReceiptRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    crate::metrics::verify_call();
    let domain = domain_for(&state, body.chain_id, body.verifying_contract).map_err(map_error)?;
    let result = verify::verify_receipt(&domain, &body.receipt, body.expected_signer.as_deref())
        .map_err(map_verify_error)?;
    Ok(Json(json!(result)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyChainRequest {
    entries: Vec<ChainEntry>,
    chain_id: Option<u64>,
    verifying_contract: Option<String>,
}

async fn verify_chain_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VerifyChainRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    crate::metrics::verify_call();
    let domain = domain_for(&state, body.chain_id, body.verifying_contract).map_err(map_error)?;
    let result = verify::verify_chain(&domain, &body.entries).map_err(map_verify_error)?;
    Ok(Json(json!(result)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyMerkleRequest {
    root: String,
    leaf: String,
    #[serde(default)]
    proof: Vec<String>,
}

async fn verify_merkle_handler(
    Json(body): Json<VerifyMerkleRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    crate::metrics::verify_call();
    let valid = verify::verify_merkle(&body.root, &body.leaf, &body.proof).map_err(map_error)?;
    Ok(Json(json!({ "valid": valid })))
}

fn not_found(message: String) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": message })))
}

/// HTTP status for a broker error (exposed for tests and clients).
pub fn status_for(err: &BrokerError) -> StatusCode {
    match err {
        BrokerError::Denied(_) => StatusCode::FORBIDDEN,
        BrokerError::NotFound(_) => StatusCode::NOT_FOUND,
        BrokerError::Invalid(_) => StatusCode::BAD_REQUEST,
        BrokerError::Throttled(_) => StatusCode::TOO_MANY_REQUESTS,
        BrokerError::NotConfigured(_) => StatusCode::NOT_IMPLEMENTED,
        BrokerError::Issuer(_) => StatusCode::BAD_GATEWAY,
        BrokerError::Receipt(_) | BrokerError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn map_error(err: BrokerError) -> (StatusCode, Json<Value>) {
    // Internal errors can contain database/OS details; log them, but do not leak them.
    if matches!(err, BrokerError::Internal(_)) {
        tracing::error!(error = %err, "internal broker error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "internal error" })),
        );
    }
    let status = status_for(&err);
    (status, Json(json!({ "error": err.to_string() })))
}

/// Verification failures are client-visible validation errors, not broker faults.
fn map_verify_error(err: BrokerError) -> (StatusCode, Json<Value>) {
    match err {
        BrokerError::Receipt(message) => map_error(BrokerError::Invalid(message)),
        other => map_error(other),
    }
}
