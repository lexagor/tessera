//! Per-tenant API keys and request authentication.
//!
//! Keys are shown once at creation and stored only as a SHA-256 hash. A request is
//! authenticated by presenting the key as `Authorization: Bearer <key>` or
//! `x-api-key: <key>`; the auth middleware resolves the tenant and inserts it into the
//! request extensions.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cache::Cache;
use crate::error::BrokerError;

/// Authenticated tenant, inserted into request extensions by the auth middleware.
#[derive(Debug, Clone)]
pub struct Tenant(pub String);

/// Optional least-privilege scope for an API key. Empty lists mean "no restriction"
/// (the tenant's policies still apply); anything present is enforced *before* policy
/// evaluation, so a restricted integration cannot even reach resources it was not issued
/// for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyScope {
    /// Resource patterns (`stripe:*`, `aws:sts.assume_role`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    /// Agent ids (exact match) this key may act as.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
    /// Allowed operations: `authorize`, `proxy`, `record`, `read`. Empty = all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Allowed upstream request paths for proxied calls (`/v1/refunds*`). Empty = all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_paths: Vec<String>,
}

/// Operations a scoped key can be granted. Key management is deliberately excluded: it stays
/// behind the admin token so a leaked integration key cannot mint more keys.
pub const KEY_CAPABILITIES: [&str; 4] = ["authorize", "proxy", "record", "read"];

/// A named scope preset, with a default budget so template keys are never unbounded.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyTemplate {
    pub name: &'static str,
    /// Preset revision. Policies pin the revision they were approved against, so changing a
    /// preset's meaning never silently changes what is enforced.
    pub version: u32,
    pub description: &'static str,
    pub scope: KeyScope,
    pub default_rate_limit_per_min: Option<u32>,
}

/// Named scope presets so integrators do not hand-write scopes (and cannot accidentally
/// over-grant). Resolved at key creation; the resolved scope is stored and audited.
pub fn key_templates() -> Vec<KeyTemplate> {
    vec![
        KeyTemplate {
            name: "monitor",
            version: 1,
            description: "read-only access to chains, evidence, and posture",
            scope: KeyScope {
                resources: vec![],
                agents: vec![],
                capabilities: vec!["read".to_string()],
                proxy_paths: vec![],
            },
            // Modest default so a template-created key is never unbounded.
            default_rate_limit_per_min: Some(60),
        },
        KeyTemplate {
            name: "payments-integration",
            version: 1,
            description: "authorize, proxy and record Stripe refunds",
            scope: KeyScope {
                resources: vec!["stripe:*".to_string()],
                agents: vec![],
                capabilities: vec![
                    "authorize".to_string(),
                    "proxy".to_string(),
                    "record".to_string(),
                ],
                // Proxy capability is bounded to the refunds endpoint by default.
                proxy_paths: vec!["/v1/refunds*".to_string()],
            },
            default_rate_limit_per_min: Some(120),
        },
        KeyTemplate {
            name: "cloud-provisioner",
            version: 1,
            description: "authorize and record AWS resources",
            scope: KeyScope {
                resources: vec!["aws:*".to_string()],
                agents: vec![],
                capabilities: vec!["authorize".to_string(), "record".to_string()],
                proxy_paths: vec![],
            },
            default_rate_limit_per_min: Some(60),
        },
        KeyTemplate {
            name: "repo-automation",
            version: 1,
            description: "authorize and record GitHub resources",
            scope: KeyScope {
                resources: vec!["github:*".to_string()],
                agents: vec![],
                capabilities: vec!["authorize".to_string(), "record".to_string()],
                proxy_paths: vec![],
            },
            default_rate_limit_per_min: Some(60),
        },
    ]
}

impl KeyScope {
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
            && self.agents.is_empty()
            && self.capabilities.is_empty()
            && self.proxy_paths.is_empty()
    }

    /// Whether the key may call an upstream path (an empty list means "any path").
    pub fn allows_proxy_path(&self, path: &str) -> bool {
        self.proxy_paths.is_empty()
            || self
                .proxy_paths
                .iter()
                .any(|pattern| crate::policy::resource_matches(pattern, path))
    }

    /// Whether the key may perform `capability` (an empty list means "all allowed").
    pub fn allows_capability(&self, capability: &str) -> bool {
        self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(capability))
    }

    /// Capabilities resolved to a concrete list (for reporting).
    pub fn effective_capabilities(&self) -> Vec<String> {
        if self.capabilities.is_empty() {
            KEY_CAPABILITIES.iter().map(|c| c.to_string()).collect()
        } else {
            self.capabilities.clone()
        }
    }

    pub fn allows_resource(&self, resource: &str) -> bool {
        self.resources.is_empty()
            || self
                .resources
                .iter()
                .any(|pattern| crate::policy::resource_matches(pattern, resource))
    }

    pub fn allows_agent(&self, agent: &str) -> bool {
        self.agents.is_empty() || self.agents.iter().any(|allowed| allowed == agent)
    }
}

/// Public metadata about an API key (never includes the secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRecord {
    pub id: String,
    pub tenant: String,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    /// Per-key request budget (requests/minute). One integration cannot exhaust the
    /// tenant's budget when its key has its own. None falls back to the tenant budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_min: Option<u32>,
    /// Least-privilege scope (resources/agents). Empty = unrestricted within the tenant.
    #[serde(default, skip_serializing_if = "KeyScope::is_empty")]
    pub scope: KeyScope,
    /// Optional expiry (RFC 3339). Expired keys behave like revoked keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// When the secret was last rotated (renewed in place, id preserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    /// Number of rotations applied to this key id.
    #[serde(default)]
    pub rotation_count: u32,
    /// Monotonic revision, bumped by every mutation (scope, budget, rotation, revocation).
    /// Used for `If-Match` optimistic concurrency on updates.
    #[serde(default)]
    pub version: u32,
}

struct StoredKey {
    record: ApiKeyRecord,
    key_hash: String,
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Create a key (or return the existing one if `plaintext` is already registered).
    /// Returns the record and the plaintext key (shown exactly once).
    async fn create(
        &self,
        tenant: &str,
        name: &str,
        plaintext: Option<String>,
        options: NewKeyOptions,
    ) -> Result<(ApiKeyRecord, String), BrokerError>;

    /// Resolve the record for a presented key, or `None` if unknown/revoked/expired.
    async fn authenticate(&self, plaintext: &str) -> Result<Option<ApiKeyRecord>, BrokerError>;

    /// Replace a key's scope and/or budget in place (the secret is unchanged). The update is
    /// conditional on `expected_version` so `If-Match` is enforced atomically, not as
    /// check-then-act.
    async fn update(
        &self,
        tenant: &str,
        id: &str,
        scope: Option<KeyScope>,
        rate_limit_per_min: Option<Option<u32>>,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<ApiKeyRecord>, BrokerError>;

    /// Rotate a key's secret in place, preserving its id, name, scope, budget and history.
    /// Returns the updated record and the new plaintext (shown once), or `None` when the
    /// key does not exist / is revoked.
    /// Renew (rotate the secret). `expected_version` makes the rotation conditional on the
    /// revision the caller saw, so a rotation cannot race a scope change.
    async fn renew(
        &self,
        tenant: &str,
        id: &str,
        expires_at: Option<String>,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<(ApiKeyRecord, String)>, BrokerError>;

    async fn list(&self, tenant: &str) -> Result<Vec<ApiKeyRecord>, BrokerError>;

    /// Revoke a key; `expected_version` makes it conditional on the revision seen.
    async fn revoke(
        &self,
        tenant: &str,
        id: &str,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<()>, BrokerError>;

    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

/// Generate a new key: `tsk_` + 24 random bytes, base64url (no padding).
pub fn generate_key() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "tsk_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Hash a key for storage/lookup.
pub fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

/// Extract a presented key from the request headers.
pub fn extract_key(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(rest) = value.strip_prefix("Bearer ") {
            let key = rest.trim();
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Constant-time string comparison (equal-length hex hashes).
/// Constant-time string comparison (no early exit on length-independent content).
pub fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Outcome of a conditional key mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutateOutcome<T> {
    /// The mutation was applied.
    Done(T),
    /// No such (live) key for this tenant.
    NotFound,
    /// The key changed since the caller's revision.
    Conflict { current: u32 },
}

/// Options applied when creating a key.
#[derive(Debug, Clone, Default)]
pub struct NewKeyOptions {
    pub rate_limit_per_min: Option<u32>,
    pub scope: KeyScope,
    /// RFC 3339 expiry; None = no expiry.
    pub expires_at: Option<String>,
}

/// How many hours past its rotation age a key is (None = not due / not applicable).
/// Age is measured from the last rotation, or creation when never rotated.
pub fn rotation_due_hours(
    record: &ApiKeyRecord,
    now: chrono::DateTime<chrono::Utc>,
    max_age_hours: u64,
) -> Option<u64> {
    if !record_is_live(record, now) {
        return None;
    }
    let reference = record
        .rotated_at
        .as_deref()
        .or(Some(record.created_at.as_str()))?;
    let rotated_at = chrono::DateTime::parse_from_rfc3339(reference).ok()?;
    let age = now - rotated_at.with_timezone(&chrono::Utc);
    let age_hours = age.num_hours().max(0) as u64;
    Some(age_hours.saturating_sub(max_age_hours))
}

/// Look up a template by name (case-insensitive).
pub fn key_template(name: &str) -> Option<KeyTemplate> {
    key_templates()
        .into_iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(name.trim()))
}

/// Whether an agent id is safe to use as an identifier and (after sanitising) a filename.
/// Agent ids are client-supplied and end up in archive entries and restore output, so path
/// separators, control characters, and traversal sequences are rejected at the boundary.
pub fn valid_agent_id(agent: &str) -> bool {
    !agent.is_empty()
        && agent.len() <= 128
        && agent
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@'))
        && !agent.contains("..")
        && !agent.starts_with('.')
        && !agent.ends_with('.')
}

/// Filesystem-safe form of an agent id. Keep common ids unchanged; for ids containing
/// other characters, append a short hash so sanitised names cannot collide.
pub fn safe_agent_filename(agent: &str) -> String {
    let sanitized: String = agent
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized == agent {
        sanitized
    } else {
        let digest = crate::merkle::keccak(agent.as_bytes());
        format!("{sanitized}-{}", hex::encode(&digest[..4]))
    }
}

/// Validate scope patterns so a typo cannot silently widen a key. Resource patterns must be
/// exact, `*`, or a provider-scoped prefix (`stripe:*`, `aws:s3:Get*`); proxy paths must be
/// absolute (`/v1/refunds*`). Returns the offending entries.
pub fn invalid_scope_patterns(scope: &KeyScope) -> Vec<String> {
    let mut invalid = Vec::new();
    for pattern in &scope.resources {
        let pattern = pattern.trim();
        let ok = pattern == "*"
            || match pattern.strip_suffix('*') {
                // A prefix wildcard must stay inside one provider: `stripe*` would also match
                // `stripeplayground:...`, so require a colon in the prefix.
                Some(prefix) => prefix.contains(':') && !prefix.is_empty(),
                None => !pattern.is_empty(),
            };
        if !ok {
            invalid.push(format!("resource pattern '{pattern}'"));
        }
    }
    for pattern in &scope.proxy_paths {
        let pattern = pattern.trim();
        // Absolute paths only: a relative pattern like `refunds*` would match unexpected
        // upstream paths once prefixed by the provider base.
        if !pattern.starts_with('/') {
            invalid.push(format!("proxy path '{pattern}'"));
        }
    }
    invalid
}

/// ETag for a key record (`"v<version>"`), suitable for `If-Match`.
pub fn key_etag(record: &ApiKeyRecord) -> String {
    format!("\"v{}\"", record.version)
}

/// Whether `scope` grants more than `template` (used for linting existing keys
/// against a preset). Returns the reasons, empty when the key stays within the template.
pub fn scope_exceeds(scope: &KeyScope, template: &KeyScope) -> Vec<String> {
    let mut reasons = Vec::new();

    // Capabilities: the template's list defines the ceiling (empty = everything allowed).
    if !template.capabilities.is_empty() {
        if scope.capabilities.is_empty() {
            reasons.push("key allows every capability".to_string());
        } else {
            for capability in &scope.capabilities {
                if !template
                    .capabilities
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(capability))
                {
                    reasons.push(format!("capability '{capability}' is outside the template"));
                }
            }
        }
    }

    // Resources: every key pattern must be covered by some template pattern.
    if !template.resources.is_empty() {
        if scope.resources.is_empty() {
            reasons.push("key allows every resource".to_string());
        } else {
            for pattern in &scope.resources {
                let covered = template
                    .resources
                    .iter()
                    .any(|allowed| pattern_covers(allowed, pattern));
                if !covered {
                    reasons.push(format!("resource '{pattern}' is outside the template"));
                }
            }
        }
    }

    // Agents: same shape as resources.
    if !template.agents.is_empty() {
        if scope.agents.is_empty() {
            reasons.push("key allows every agent".to_string());
        } else {
            for agent in &scope.agents {
                if !template
                    .agents
                    .iter()
                    .any(|allowed| pattern_covers(allowed, agent))
                {
                    reasons.push(format!("agent '{agent}' is outside the template"));
                }
            }
        }
    }

    // Proxy paths: the template's allowlist is the ceiling.
    if !template.proxy_paths.is_empty() {
        if scope.proxy_paths.is_empty() {
            reasons.push("key allows every upstream path".to_string());
        } else {
            for pattern in &scope.proxy_paths {
                let covered = template
                    .proxy_paths
                    .iter()
                    .any(|allowed| pattern_covers(allowed, pattern));
                if !covered {
                    reasons.push(format!("proxy path '{pattern}' is outside the template"));
                }
            }
        }
    }

    reasons
}

/// Whether `allowed` (a pattern) covers `requested` (another pattern), where `*` and
/// trailing-`*` prefixes are supported.
fn pattern_covers(allowed: &str, requested: &str) -> bool {
    if allowed == "*" || allowed == requested {
        return true;
    }
    match allowed.strip_suffix('*') {
        Some(prefix) => requested.starts_with(prefix),
        None => false,
    }
}

/// Key posture summary (active / expiring soon / rotation due) for dashboards and snapshots.
pub fn key_posture(
    records: &[ApiKeyRecord],
    now: chrono::DateTime<chrono::Utc>,
    expiry_alert_days: u64,
    rotation_max_age_hours: Option<u64>,
) -> serde_json::Value {
    let mut active = 0usize;
    let mut expiring_soon = 0usize;
    let mut rotation_due = 0usize;
    for record in records {
        if !record_is_live(record, now) {
            continue;
        }
        active += 1;
        if let Some(raw) = record.expires_at.as_deref() {
            if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(raw) {
                let expires_at = expires_at.with_timezone(&chrono::Utc);
                if expires_at <= now + chrono::Duration::days(expiry_alert_days as i64) {
                    expiring_soon += 1;
                }
            }
        }
        if let Some(max_age) = rotation_max_age_hours {
            if rotation_due_hours(record, now, max_age).is_some() {
                rotation_due += 1;
            }
        }
    }
    serde_json::json!({
        "active": active,
        "expiringSoon": expiring_soon,
        "rotationDue": rotation_due,
    })
}

/// Whether a record may be used at `now` (not revoked, not expired).
pub fn record_is_live(record: &ApiKeyRecord, now: chrono::DateTime<chrono::Utc>) -> bool {
    if record.revoked_at.is_some() {
        return false;
    }
    match record.expires_at.as_deref() {
        Some(raw) => match chrono::DateTime::parse_from_rfc3339(raw) {
            Ok(expires_at) => expires_at.with_timezone(&chrono::Utc) > now,
            // An unparseable expiry is treated as expired: fail closed.
            Err(_) => false,
        },
        None => true,
    }
}

pub fn new_record(tenant: &str, name: &str, plaintext: &str) -> ApiKeyRecord {
    ApiKeyRecord {
        id: format!("key_{}", uuid::Uuid::new_v4().simple()),
        tenant: tenant.to_string(),
        name: name.to_string(),
        prefix: plaintext.chars().take(12).collect(),
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        revoked_at: None,
        rate_limit_per_min: None,
        scope: KeyScope::default(),
        expires_at: None,
        rotated_at: None,
        rotation_count: 0,
        version: 1,
    }
}

#[derive(Default)]
pub struct MemoryApiKeyStore {
    keys: Mutex<Vec<StoredKey>>,
}

impl MemoryApiKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<StoredKey>>, BrokerError> {
        self.keys
            .lock()
            .map_err(|_| BrokerError::Internal("api key store poisoned".into()))
    }
}

#[async_trait]
impl ApiKeyStore for MemoryApiKeyStore {
    async fn create(
        &self,
        tenant: &str,
        name: &str,
        plaintext: Option<String>,
        options: NewKeyOptions,
    ) -> Result<(ApiKeyRecord, String), BrokerError> {
        let plaintext = plaintext.unwrap_or_else(generate_key);
        let hash = hash_key(&plaintext);
        let mut keys = self.lock()?;
        if let Some(existing) = keys.iter().find(|k| k.key_hash == hash) {
            return Ok((existing.record.clone(), plaintext));
        }
        let mut record = new_record(tenant, name, &plaintext);
        record.rate_limit_per_min = options.rate_limit_per_min;
        record.scope = options.scope;
        record.expires_at = options.expires_at;
        keys.push(StoredKey {
            record: record.clone(),
            key_hash: hash,
        });
        Ok((record, plaintext))
    }

    async fn authenticate(&self, plaintext: &str) -> Result<Option<ApiKeyRecord>, BrokerError> {
        let hash = hash_key(plaintext);
        let now = chrono::Utc::now();
        Ok(self
            .lock()?
            .iter()
            .find(|k| ct_eq(&k.key_hash, &hash) && record_is_live(&k.record, now))
            .map(|k| k.record.clone()))
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ApiKeyRecord>, BrokerError> {
        let mut records: Vec<ApiKeyRecord> = self
            .lock()?
            .iter()
            .filter(|k| k.record.tenant == tenant)
            .map(|k| k.record.clone())
            .collect();
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(records)
    }

    async fn update(
        &self,
        tenant: &str,
        id: &str,
        scope: Option<KeyScope>,
        rate_limit_per_min: Option<Option<u32>>,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<ApiKeyRecord>, BrokerError> {
        let mut keys = self.lock()?;
        let Some(key) = keys.iter_mut().find(|k| {
            k.record.tenant == tenant && k.record.id == id && k.record.revoked_at.is_none()
        }) else {
            return Ok(MutateOutcome::NotFound);
        };
        if let Some(expected) = expected_version {
            if key.record.version != expected {
                return Ok(MutateOutcome::Conflict {
                    current: key.record.version,
                });
            }
        }
        if let Some(scope) = scope {
            key.record.scope = scope;
        }
        if let Some(limit) = rate_limit_per_min {
            key.record.rate_limit_per_min = limit;
        }
        key.record.version = key.record.version.saturating_add(1);
        Ok(MutateOutcome::Done(key.record.clone()))
    }

    async fn renew(
        &self,
        tenant: &str,
        id: &str,
        expires_at: Option<String>,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<(ApiKeyRecord, String)>, BrokerError> {
        let plaintext = generate_key();
        let hash = hash_key(&plaintext);
        let mut keys = self.lock()?;
        let Some(key) = keys.iter_mut().find(|k| {
            k.record.tenant == tenant && k.record.id == id && k.record.revoked_at.is_none()
        }) else {
            return Ok(MutateOutcome::NotFound);
        };
        if let Some(expected) = expected_version {
            if key.record.version != expected {
                return Ok(MutateOutcome::Conflict {
                    current: key.record.version,
                });
            }
        }
        key.key_hash = hash;
        key.record.prefix = plaintext.chars().take(12).collect();
        key.record.expires_at = expires_at;
        key.record.rotated_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        key.record.rotation_count = key.record.rotation_count.saturating_add(1);
        key.record.version = key.record.version.saturating_add(1);
        Ok(MutateOutcome::Done((key.record.clone(), plaintext)))
    }

    async fn revoke(
        &self,
        tenant: &str,
        id: &str,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<()>, BrokerError> {
        let mut keys = self.lock()?;
        let Some(key) = keys.iter_mut().find(|k| {
            k.record.tenant == tenant && k.record.id == id && k.record.revoked_at.is_none()
        }) else {
            return Ok(MutateOutcome::NotFound);
        };
        if let Some(expected) = expected_version {
            if key.record.version != expected {
                return Ok(MutateOutcome::Conflict {
                    current: key.record.version,
                });
            }
        }
        key.record.revoked_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        key.record.version = key.record.version.saturating_add(1);
        Ok(MutateOutcome::Done(()))
    }
}

/// Decorates an [`ApiKeyStore`] with a cache of `key hash -> tenant`, so authorization does
/// not hit the database on every request. State-changing calls clear the cache.
pub struct CachedApiKeyStore {
    inner: Arc<dyn ApiKeyStore>,
    cache: Arc<dyn Cache>,
    ttl_secs: u64,
}

impl CachedApiKeyStore {
    pub fn new(inner: Arc<dyn ApiKeyStore>, cache: Arc<dyn Cache>, ttl_secs: u64) -> Self {
        Self {
            inner,
            cache,
            ttl_secs,
        }
    }

    fn cache_key(plaintext: &str) -> String {
        format!("tessera:apikey:{}", hash_key(plaintext))
    }
}

#[async_trait]
impl ApiKeyStore for CachedApiKeyStore {
    async fn create(
        &self,
        tenant: &str,
        name: &str,
        plaintext: Option<String>,
        options: NewKeyOptions,
    ) -> Result<(ApiKeyRecord, String), BrokerError> {
        let result = self.inner.create(tenant, name, plaintext, options).await?;
        let _ = self.cache.clear().await;
        Ok(result)
    }

    async fn authenticate(&self, plaintext: &str) -> Result<Option<ApiKeyRecord>, BrokerError> {
        let key = Self::cache_key(plaintext);
        if let Ok(Some(cached)) = self.cache.get(&key).await {
            if let Ok(record) = serde_json::from_str::<ApiKeyRecord>(&cached) {
                return Ok(Some(record));
            }
        }
        let record = self.inner.authenticate(plaintext).await?;
        if let Some(record) = &record {
            if let Ok(encoded) = serde_json::to_string(record) {
                // Never cache a key past its own expiry.
                let ttl = match record.expires_at.as_deref() {
                    Some(raw) => chrono::DateTime::parse_from_rfc3339(raw)
                        .map(|expires_at| {
                            let remaining =
                                expires_at.with_timezone(&chrono::Utc) - chrono::Utc::now();
                            remaining.num_seconds().max(0) as u64
                        })
                        .unwrap_or(0)
                        .min(self.ttl_secs),
                    None => self.ttl_secs,
                };
                let _ = self.cache.put(&key, &encoded, ttl).await;
            }
        }
        Ok(record)
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ApiKeyRecord>, BrokerError> {
        self.inner.list(tenant).await
    }

    async fn update(
        &self,
        tenant: &str,
        id: &str,
        scope: Option<KeyScope>,
        rate_limit_per_min: Option<Option<u32>>,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<ApiKeyRecord>, BrokerError> {
        let result = self
            .inner
            .update(tenant, id, scope, rate_limit_per_min, expected_version)
            .await?;
        if matches!(result, MutateOutcome::Done(_)) {
            let _ = self.cache.clear().await;
        }
        Ok(result)
    }

    async fn renew(
        &self,
        tenant: &str,
        id: &str,
        expires_at: Option<String>,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<(ApiKeyRecord, String)>, BrokerError> {
        let result = self
            .inner
            .renew(tenant, id, expires_at, expected_version)
            .await?;
        if matches!(result, MutateOutcome::Done(_)) {
            let _ = self.cache.clear().await;
        }
        Ok(result)
    }

    async fn revoke(
        &self,
        tenant: &str,
        id: &str,
        expected_version: Option<u32>,
    ) -> Result<MutateOutcome<()>, BrokerError> {
        let result = self.inner.revoke(tenant, id, expected_version).await?;
        if matches!(result, MutateOutcome::Done(_)) {
            let _ = self.cache.clear().await;
        }
        Ok(result)
    }

    async fn migrate(&self) -> Result<(), BrokerError> {
        self.inner.migrate().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_pattern_validation_catches_cross_provider_wildcards() {
        let scope = |resources: Vec<&str>, paths: Vec<&str>| KeyScope {
            resources: resources.into_iter().map(str::to_string).collect(),
            agents: vec![],
            capabilities: vec![],
            proxy_paths: paths.into_iter().map(str::to_string).collect(),
        };
        assert!(invalid_scope_patterns(&scope(vec![], vec![])).is_empty());
        assert!(
            invalid_scope_patterns(&scope(vec!["*", "stripe:*", "aws:s3:Get*"], vec![])).is_empty()
        );
        assert!(invalid_scope_patterns(&scope(vec![], vec!["/", "/v1/refunds*"])).is_empty());
        assert_eq!(
            invalid_scope_patterns(&scope(vec!["stripe*"], vec![])),
            vec!["resource pattern 'stripe*'".to_string()]
        );
        assert_eq!(
            invalid_scope_patterns(&scope(vec![], vec!["refunds*"])),
            vec!["proxy path 'refunds*'".to_string()]
        );
        assert_eq!(
            invalid_scope_patterns(&scope(vec![""], vec![])).len(),
            1,
            "empty patterns are invalid"
        );
    }

    #[test]
    fn rotation_age_is_measured_from_the_last_rotation() {
        let now = chrono::Utc::now();
        let mut record = new_record("acme", "ci", "tsk_x");
        record.created_at = (now - chrono::Duration::hours(100)).to_rfc3339();
        // Never rotated: age counts from creation.
        assert_eq!(rotation_due_hours(&record, now, 48), Some(52));
        assert_eq!(rotation_due_hours(&record, now, 200), Some(0));
        // After a rotation the clock resets.
        record.rotated_at = Some((now - chrono::Duration::hours(10)).to_rfc3339());
        assert_eq!(rotation_due_hours(&record, now, 48), Some(0));
        assert_eq!(rotation_due_hours(&record, now, 5), Some(5));
        // Revoked or expired keys are not "due" (they need replacement, not rotation).
        record.revoked_at = Some(now.to_rfc3339());
        assert_eq!(rotation_due_hours(&record, now, 1), None);
    }

    #[tokio::test]
    async fn create_authenticate_revoke() {
        let store = MemoryApiKeyStore::new();
        let (record, key) = store
            .create("acme", "ci", None, Default::default())
            .await
            .unwrap();
        assert!(key.starts_with("tsk_"));
        assert_eq!(record.tenant, "acme");
        assert_eq!(
            store
                .authenticate(&key)
                .await
                .unwrap()
                .map(|r| r.tenant)
                .as_deref(),
            Some("acme")
        );
        assert_eq!(store.list("acme").await.unwrap().len(), 1);

        assert_eq!(
            store.revoke("acme", &record.id, None).await.unwrap(),
            MutateOutcome::Done(())
        );
        assert!(store.authenticate(&key).await.unwrap().is_none());
        assert_eq!(
            store.revoke("acme", &record.id, None).await.unwrap(),
            MutateOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn idempotent_for_same_plaintext() {
        let store = MemoryApiKeyStore::new();
        let (a, k1) = store
            .create("t", "a", Some("tsk_fixed".into()), Default::default())
            .await
            .unwrap();
        let (b, k2) = store
            .create("t", "b", Some("tsk_fixed".into()), Default::default())
            .await
            .unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(k1, k2);
        assert_eq!(store.list("t").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let store = MemoryApiKeyStore::new();
        let (_r, key) = store
            .create("acme", "a", None, Default::default())
            .await
            .unwrap();
        assert_eq!(
            store
                .authenticate(&key)
                .await
                .unwrap()
                .map(|r| r.tenant)
                .as_deref(),
            Some("acme")
        );
        assert!(store.list("other").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cached_store_caches_and_invalidates() {
        let inner = Arc::new(MemoryApiKeyStore::new());
        let (record, key) = inner
            .create("acme", "t", None, Default::default())
            .await
            .unwrap();
        let cache = Arc::new(crate::cache::MemoryCache::new());
        let store = CachedApiKeyStore::new(inner, cache, 60);

        assert_eq!(
            store
                .authenticate(&key)
                .await
                .unwrap()
                .map(|r| r.tenant)
                .as_deref(),
            Some("acme")
        );
        // revoking clears the cache, so the key stops authenticating
        assert_eq!(
            store.revoke("acme", &record.id, None).await.unwrap(),
            MutateOutcome::Done(())
        );
        assert!(store.authenticate(&key).await.unwrap().is_none());
    }

    #[test]
    fn extract_key_reads_bearer_and_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer tsk_abc".parse().unwrap());
        assert_eq!(extract_key(&headers).as_deref(), Some("tsk_abc"));

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", "tsk_xyz".parse().unwrap());
        assert_eq!(extract_key(&headers).as_deref(), Some("tsk_xyz"));
    }
}
