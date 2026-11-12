//! Environment-driven configuration.

use std::collections::HashMap;

#[derive(Clone)]
pub struct AwsConfig {
    pub region: String,
    pub role_arn: String,
    pub session_name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    /// Override the STS endpoint (tests / private endpoints). Defaults to
    /// `https://sts.<region>.amazonaws.com`.
    pub endpoint_override: Option<String>,
    /// Override the IAM endpoint (tests / private endpoints). Defaults to
    /// `https://iam.amazonaws.com`.
    pub iam_endpoint_override: Option<String>,
}

impl std::fmt::Debug for AwsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsConfig")
            .field("region", &self.region)
            .field("role_arn", &self.role_arn)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct GithubConfig {
    pub app_id: u64,
    pub private_key_pem: String,
    pub api_base: String,
}

impl std::fmt::Debug for GithubConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubConfig")
            .field("app_id", &self.app_id)
            .field("private_key_pem", &"<redacted>")
            .field("api_base", &self.api_base)
            .finish()
    }
}

#[derive(Clone)]
pub struct StripeConfig {
    /// Mapping of `scope key` -> restricted key, e.g. `charges_create` -> `rk_live_...`
    pub restricted_keys: HashMap<String, String>,
    /// Upstream API base used by the broker proxy. Override for tests/enterprise.
    pub api_base: String,
}

impl std::fmt::Debug for StripeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripeConfig")
            .field(
                "restricted_keys",
                &format!("<{} redacted>", self.restricted_keys.len()),
            )
            .field("api_base", &self.api_base)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AnchorConfig {
    pub rpc_url: String,
    /// Local signing key. Optional when a KMS/HSM signer is configured.
    pub private_key: Option<String>,
    pub contract: String,
}

impl AnchorConfig {
    pub fn from_env() -> Option<Self> {
        let rpc_url = std::env::var("RPC_URL").ok().filter(|s| !s.is_empty())?;
        let private_key = std::env::var("ANCHOR_PK").ok().filter(|s| !s.is_empty());
        let contract = std::env::var("RECEIPT_ANCHOR_ADDRESS")
            .ok()
            .filter(|s| !s.is_empty() && s != "0x0000000000000000000000000000000000000000")?;
        Some(Self {
            rpc_url,
            private_key,
            contract,
        })
    }
}

/// Parse `TOOL_RATE_LIMITS="resource=per_minute,..."` (unknown entries are ignored).
pub fn parse_tool_rate_limits(raw: &str) -> Vec<(String, u32)> {
    let mut limits = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((resource, per_minute)) = entry.rsplit_once('=') else {
            tracing::warn!(entry, "ignoring malformed TOOL_RATE_LIMITS entry");
            continue;
        };
        match per_minute.trim().parse::<u32>() {
            Ok(n) if n > 0 && !resource.trim().is_empty() => {
                limits.push((resource.trim().to_string(), n));
            }
            _ => tracing::warn!(entry, "ignoring malformed TOOL_RATE_LIMITS entry"),
        }
    }
    limits
}

/// Parse `TESSERA_DEMO_ALLOW`. **Fail-safe default: disabled.** Demo mode grants full tenant
/// access without an API key (the `x-tessera-tenant` header), injects a permissive policy,
/// and treats every caller as an admin for settings/key management, so it must be opted into
/// explicitly.
pub fn demo_allow_from(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Anchor fee ceiling in wei, from `ANCHOR_MAX_FEE_PER_GAS_WEI` (empty/unset = no cap).
pub fn anchor_max_fee_per_gas() -> Option<u128> {
    std::env::var("ANCHOR_MAX_FEE_PER_GAS_WEI")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| value.trim().parse().ok())
}

#[derive(Debug, Clone, Default)]
pub struct BrokerConfig {
    pub host: String,
    pub port: u16,
    /// 32-byte secp256k1 key, hex (with or without 0x).
    pub signing_key_hex: Option<String>,
    /// Previously used broker signer addresses (comma-separated), so receipts signed
    /// before a key rotation remain verifiable.
    pub signing_key_history: Vec<String>,
    pub chain_id: u64,
    pub verifying_contract: String,
    pub aws: Option<AwsConfig>,
    pub github: Option<GithubConfig>,
    pub stripe: Option<StripeConfig>,
    /// When set, use the Postgres-backed receipt chain; otherwise in-memory.
    pub database_url: Option<String>,
    /// When set, use Redis for the API-key cache; otherwise in-memory.
    pub redis_url: Option<String>,
    /// When true, tenants with no configured policy get a permissive demo policy and the
    /// broker accepts the `x-tessera-tenant` header without an API key.
    pub demo_allow: bool,
    /// Admin token that authorizes API-key management.
    pub admin_token: Option<String>,
    /// Plaintext key seeded for tenant `default` in demo mode.
    pub demo_key: String,
    /// If set, a key for this tenant is created at startup and printed once.
    pub bootstrap_tenant: Option<String>,
    /// On-chain receipt anchoring (RPC + key + deployed contract).
    pub anchor: Option<AnchorConfig>,
    /// Background anchor sweep interval in seconds (0/None disables scheduling).
    pub anchor_interval_secs: Option<u64>,
    /// Per-tenant request budget (requests/minute). None disables rate limiting.
    pub rate_limit_per_min: Option<u32>,
    /// Per-IP budget for public routes (verify/metrics), requests/minute. None disables.
    pub public_rate_limit_per_min: Option<u32>,
    /// Per-agent budget (requests/minute). None disables.
    pub agent_rate_limit_per_min: Option<u32>,
    /// Per-resource budgets (`resource=per_minute`), e.g. `stripe:refunds.create=10`.
    pub tool_rate_limits: Vec<(String, u32)>,
    /// Default credential lifetime in seconds.
    pub default_credential_ttl_seconds: u32,
    /// Hard ceiling on credential lifetime in seconds.
    pub max_credential_ttl_seconds: u32,
    /// Retention window (days) for terminal anchors and idle telemetry. 0 disables.
    pub retention_days: u64,
    /// Warn (and count) when a live chain has grown this many receipts past its last anchor.
    pub anchor_gap_threshold: u64,
    /// Days after which key-event ledger entries are compacted behind a signed checkpoint
    /// (0 keeps everything).
    pub ledger_retention_days: u64,
    /// Directory for scheduled tenant archive files (tar.gz). Empty disables.
    pub archive_dir: Option<String>,
    /// Seconds between scheduled tenant archives (default 3600).
    pub archive_interval_secs: u64,
    /// Second location each archive is copied to (verified by digest). Empty disables.
    pub archive_replica_dir: Option<String>,
    /// Days after which archive/snapshot files are pruned (0 keeps everything).
    pub archive_retention_days: u64,
    /// Webhook URL notified when a chain crosses the anchor gap threshold. Empty disables.
    pub alert_webhook_url: Option<String>,
    /// Shared secret sent as `x-tessera-alert-token` with alert webhooks.
    pub alert_webhook_token: Option<String>,
    /// Minimum seconds between repeat alerts for the same (tenant, agent).
    pub alert_repeat_secs: u64,
    /// Seconds before retrying a failed alert delivery (default 60).
    pub alert_retry_secs: u64,
    /// Days before expiry at which API keys are reported/altered (0 disables, default 7).
    pub key_expiry_alert_days: u64,
    /// Alerts at or below this severity are auto-acknowledged (counted, not delivered).
    pub alert_auto_ack_below: Option<u64>,
    /// Hours after which an un-rotated API key is reported (empty disables; 0 = always due).
    pub key_rotation_max_age_hours: Option<u64>,
    /// Provider-wide in-flight cap per provider (0 disables).
    pub provider_max_inflight: usize,
    /// Per-tenant in-flight cap per provider (0 disables).
    pub provider_max_inflight_per_tenant: usize,
    /// Blocks on top of an anchor tx before it is considered final.
    pub anchor_confirmations: u64,
    /// Seconds a submitted anchor may stay unmined before it is assumed reorged out.
    pub anchor_reorg_grace_secs: u64,
    /// ChaCha20-Poly1305 key (32-byte hex) used to encrypt tenant secrets at rest.
    pub tenant_secret_enc_key: Option<String>,
    /// KMS/HSM bridge URL. When set, receipt and anchor signing are delegated to it.
    pub kms_signer_url: Option<String>,
    /// Address of the KMS signer (used for verification/records).
    pub kms_signer_address: Option<String>,
}

impl BrokerConfig {
    pub fn from_env() -> Self {
        Self {
            host: env_or("BROKER_HOST", "0.0.0.0"),
            port: env_or("BROKER_PORT", "8787").parse().unwrap_or(8787),
            signing_key_hex: std::env::var("BROKER_SIGNING_KEY").ok(),
            signing_key_history: std::env::var("BROKER_SIGNING_KEY_HISTORY")
                .ok()
                .map(|raw| {
                    raw.split(',')
                        .map(|entry| entry.trim().to_string())
                        .filter(|entry| !entry.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            chain_id: env_or("CHAIN_ID", "84532").parse().unwrap_or(84532),
            verifying_contract: env_or(
                "RECEIPT_ANCHOR_ADDRESS",
                "0x0000000000000000000000000000000000000000",
            ),
            aws: AwsConfig::from_env(),
            github: GithubConfig::from_env(),
            stripe: StripeConfig::from_env(),
            database_url: std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty()),
            redis_url: std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty()),
            demo_allow: demo_allow_from(std::env::var("TESSERA_DEMO_ALLOW").ok().as_deref()),
            admin_token: std::env::var("TESSERA_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            demo_key: env_or("TESSERA_DEMO_KEY", "tsk_demo_local"),
            bootstrap_tenant: std::env::var("TESSERA_BOOTSTRAP_TENANT")
                .ok()
                .filter(|s| !s.is_empty()),
            anchor: AnchorConfig::from_env(),
            anchor_interval_secs: std::env::var("ANCHOR_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|n| *n > 0),
            rate_limit_per_min: std::env::var("RATE_LIMIT_PER_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|n| *n > 0),
            // Public routes are limited by default (120/min per IP); set 0 to disable.
            public_rate_limit_per_min: match std::env::var("PUBLIC_RATE_LIMIT_PER_MIN").ok() {
                Some(v) => v.parse::<u32>().ok().filter(|n| *n > 0),
                None => Some(120),
            },
            agent_rate_limit_per_min: std::env::var("AGENT_RATE_LIMIT_PER_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|n| *n > 0),
            tool_rate_limits: std::env::var("TOOL_RATE_LIMITS")
                .ok()
                .map(|raw| parse_tool_rate_limits(&raw))
                .unwrap_or_default(),
            default_credential_ttl_seconds: std::env::var("DEFAULT_CREDENTIAL_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            max_credential_ttl_seconds: std::env::var("MAX_CREDENTIAL_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            ledger_retention_days: std::env::var("LEDGER_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            anchor_gap_threshold: std::env::var("ANCHOR_GAP_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            archive_dir: std::env::var("ARCHIVE_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            archive_interval_secs: std::env::var("ARCHIVE_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            archive_replica_dir: std::env::var("ARCHIVE_REPLICA_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            archive_retention_days: std::env::var("ARCHIVE_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            alert_webhook_url: std::env::var("ALERT_WEBHOOK_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            alert_webhook_token: std::env::var("ALERT_WEBHOOK_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            alert_repeat_secs: std::env::var("ALERT_REPEAT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            alert_retry_secs: std::env::var("ALERT_RETRY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            key_expiry_alert_days: std::env::var("KEY_EXPIRY_ALERT_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7),
            alert_auto_ack_below: std::env::var("ALERT_AUTO_ACK_BELOW")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .and_then(|s| s.parse().ok()),
            key_rotation_max_age_hours: std::env::var("KEY_ROTATION_MAX_AGE_HOURS")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .and_then(|s| s.parse().ok()),
            provider_max_inflight: std::env::var("PROVIDER_MAX_INFLIGHT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            provider_max_inflight_per_tenant: std::env::var("PROVIDER_MAX_INFLIGHT_PER_TENANT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            retention_days: std::env::var("RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            anchor_confirmations: std::env::var("ANCHOR_CONFIRMATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(12),
            anchor_reorg_grace_secs: std::env::var("ANCHOR_REORG_GRACE_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
            tenant_secret_enc_key: std::env::var("TENANT_SECRET_ENC_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            kms_signer_url: std::env::var("KMS_SIGNER_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            kms_signer_address: std::env::var("KMS_SIGNER_ADDRESS")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

impl AwsConfig {
    pub fn from_env() -> Option<Self> {
        let region = std::env::var("AWS_REGION").ok()?;
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let role_arn = std::env::var("AWS_ROLE_ARN").ok()?;
        Some(Self {
            region,
            role_arn,
            session_name: env_or("AWS_SESSION_NAME", "tessera-agent"),
            access_key_id,
            secret_access_key,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            endpoint_override: std::env::var("AWS_STS_ENDPOINT").ok(),
            iam_endpoint_override: std::env::var("AWS_IAM_ENDPOINT").ok(),
        })
    }
}

impl GithubConfig {
    pub fn from_env() -> Option<Self> {
        let app_id = std::env::var("GITHUB_APP_ID").ok()?.parse().ok()?;
        let private_key_pem = std::env::var("GITHUB_APP_PRIVATE_KEY").ok()?;
        Some(Self {
            app_id,
            private_key_pem,
            api_base: env_or("GITHUB_API_BASE", "https://api.github.com"),
        })
    }
}

impl StripeConfig {
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("STRIPE_RESTRICTED_KEYS").ok()?;
        let mut restricted_keys = HashMap::new();
        for pair in raw.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                restricted_keys.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        if restricted_keys.is_empty() {
            None
        } else {
            Some(Self {
                restricted_keys,
                api_base: env_or("STRIPE_API_BASE", "https://api.stripe.com"),
            })
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_mode_is_opt_in_only() {
        // Unset, empty, or unrecognized values must all mean "auth required".
        assert!(!demo_allow_from(None));
        assert!(!demo_allow_from(Some("")));
        assert!(!demo_allow_from(Some("0")));
        assert!(!demo_allow_from(Some("false")));
        assert!(!demo_allow_from(Some("maybe")));
        assert!(!demo_allow_from(Some("2")));
        // Explicit opt-ins are accepted in common spellings.
        assert!(demo_allow_from(Some("1")));
        assert!(demo_allow_from(Some(" TRUE ")));
        assert!(demo_allow_from(Some("yes")));
    }

    #[test]
    fn tool_rate_limits_parse_and_skip_junk() {
        let limits = parse_tool_rate_limits(
            "stripe:refunds.create=10, aws:sts.assume_role=5,,broken,=4,github:x=0",
        );
        assert_eq!(
            limits,
            vec![
                ("stripe:refunds.create".to_string(), 10),
                ("aws:sts.assume_role".to_string(), 5),
            ]
        );
        assert!(parse_tool_rate_limits("").is_empty());
    }
}
