//! Service bootstrap: assemble policy store, issuers, and receipt signer from config.

use std::sync::Arc;

use crate::anchoring::{
    AnchorStore, AnchorTargetStore, MemoryAnchorStore, MemoryAnchorTargetStore,
};
use crate::anchoring_pg::PostgresAnchoring;
use crate::auth::{ApiKeyStore, CachedApiKeyStore, MemoryApiKeyStore};
use crate::auth_pg::PostgresApiKeyStore;
use crate::authorize::AuthorizeService;
use crate::cache::{Cache, MemoryCache, RedisCache};
use crate::chain::{ChainStore, MemoryChainStore};
use crate::chain_pg::PostgresChainStore;
use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::eth::AnchorSubmitter;
use crate::http::AppState;
use crate::issuers::aws_sts::AwsStsIssuer;
use crate::issuers::github::GithubIssuer;
use crate::issuers::mock::MockIssuer;
use crate::issuers::stripe::{GrantStore, PostgresGrantStore, StripeIssuer};
use crate::issuers::IssuerRegistry;
use crate::policy::{demo_policy, InMemoryPolicyStore, PolicyStore};
use crate::policy_pg::PostgresPolicyStore;
use crate::receipt::ReceiptSigner;
use crate::revocation::{MemoryRevocationStore, RevocationStore};
use crate::revocation_pg::PostgresRevocationStore;
use crate::signer::{DigestSigner, HttpKmsSigner, LocalSigner};
use crate::telemetry::{MemoryTelemetryStore, TelemetryStore};
use crate::telemetry_pg::PostgresTelemetryStore;

pub async fn build_service(cfg: &BrokerConfig) -> Result<Arc<AuthorizeService>, BrokerError> {
    let signer = match &cfg.kms_signer_url {
        Some(url) => Arc::new(ReceiptSigner::with_backend(
            Arc::new(HttpKmsSigner::new(
                url,
                cfg.kms_signer_address.as_deref().unwrap_or_default(),
            )),
            cfg.chain_id,
            &cfg.verifying_contract,
            true,
        )?),
        None => Arc::new(ReceiptSigner::from_hex_or_random(
            cfg.signing_key_hex.as_deref(),
            cfg.chain_id,
            &cfg.verifying_contract,
        )?),
    };

    if !cfg.demo_allow && !signer.is_deterministic() {
        return Err(BrokerError::Invalid(
            "BROKER_SIGNING_KEY (or KMS_SIGNER_URL) must be set outside demo mode: a stable \
             signer is required so receipt signatures remain verifiable across restarts"
                .into(),
        ));
    }

    let policies: Arc<dyn PolicyStore> = match &cfg.database_url {
        Some(url) => Arc::new(PostgresPolicyStore::new(url)?),
        None => Arc::new(InMemoryPolicyStore::new()),
    };
    let demo_policy = if cfg.demo_allow {
        Some(demo_policy())
    } else {
        None
    };

    let authority_require_token = crate::config::demo_allow_from(
        std::env::var("TESSERA_AUTHORITY_REQUIRE_TOKEN")
            .ok()
            .as_deref(),
    );
    let authority_kid = std::env::var("TESSERA_AUTHORITY_KID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "v1".to_string());
    let previous_kid = std::env::var("TESSERA_AUTHORITY_PREVIOUS_KID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "v0".to_string());
    if authority_kid.len() > 64 || previous_kid.len() > 64 {
        return Err(BrokerError::Invalid(
            "authority key ids must be 1..=64 bytes".into(),
        ));
    }
    let mut authority_keys = Vec::new();
    if let Some(secret) = std::env::var("TESSERA_AUTHORITY_HMAC_SECRET")
        .ok()
        .filter(|value| !value.is_empty())
    {
        if secret.len() < 32 {
            return Err(BrokerError::Invalid(
                "TESSERA_AUTHORITY_HMAC_SECRET must be at least 32 bytes".into(),
            ));
        }
        authority_keys.push(crate::authority::AuthorityKey {
            kid: authority_kid.clone(),
            secret,
        });
    }
    if let Some(secret) = std::env::var("TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS")
        .ok()
        .filter(|value| !value.is_empty())
    {
        if secret.len() < 32 {
            return Err(BrokerError::Invalid(
                "TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS must be at least 32 bytes".into(),
            ));
        }
        if previous_kid == authority_kid {
            return Err(BrokerError::Invalid(
                "TESSERA_AUTHORITY_PREVIOUS_KID must differ from TESSERA_AUTHORITY_KID".into(),
            ));
        }
        authority_keys.push(crate::authority::AuthorityKey {
            kid: previous_kid,
            secret,
        });
    }
    let authority_replay: Arc<dyn Cache> = match &cfg.redis_url {
        Some(url) => Arc::new(RedisCache::connect(url).await?),
        None => Arc::new(MemoryCache::with_capacity(100_000)),
    };
    let authority = crate::authority::AuthorityVerifier {
        keys: authority_keys,
        issuer: std::env::var("TESSERA_AUTHORITY_ISSUER")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "tessera-api".to_string()),
        audience: std::env::var("TESSERA_AUTHORITY_AUDIENCE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "tessera-broker".to_string()),
        require_token: authority_require_token,
        replay: authority_replay,
    };

    let secrets = match &cfg.tenant_secret_enc_key {
        Some(key) => Some(Arc::new(crate::secrets::Envelope::from_hex(key)?)),
        None => None,
    };

    let mut issuers = IssuerRegistry::new();
    match &cfg.aws {
        Some(aws) => issuers.register(Arc::new(AwsStsIssuer::new(aws.clone()))),
        None if cfg.demo_allow => issuers.register(Arc::new(MockIssuer::new("aws"))),
        None => {}
    }
    match &cfg.github {
        Some(github) => issuers.register(Arc::new(GithubIssuer::new(github.clone()))),
        None if cfg.demo_allow => issuers.register(Arc::new(MockIssuer::new("github"))),
        None => {}
    }
    match &cfg.stripe {
        Some(stripe) => {
            let issuer = match &cfg.database_url {
                Some(url) => {
                    let store = Arc::new(PostgresGrantStore::new(url, secrets.clone())?);
                    store.migrate().await?;
                    StripeIssuer::with_store(stripe.clone(), store)
                }
                None => StripeIssuer::new(stripe.clone()),
            };
            issuers.register(Arc::new(issuer));
        }
        None if cfg.demo_allow => issuers.register(Arc::new(MockIssuer::new("stripe"))),
        None => {}
    }
    if cfg.demo_allow {
        // Demo coverage for providers whose production issuer is not wired yet. This keeps
        // integration setup and end-to-end UI flows testable without pretending a live
        // adapter exists.
        for provider in ["slack", "zendesk", "openai", "anthropic", "langchain"] {
            if !issuers
                .providers()
                .iter()
                .any(|registered| registered == provider)
            {
                issuers.register(Arc::new(MockIssuer::new(provider)));
            }
        }
    }

    let chain: Arc<dyn ChainStore> = match &cfg.database_url {
        Some(url) => Arc::new(PostgresChainStore::new(url)?),
        None => Arc::new(MemoryChainStore::new()),
    };

    let telemetry: Arc<dyn TelemetryStore> = match &cfg.database_url {
        Some(url) => Arc::new(PostgresTelemetryStore::new(url)?),
        None => Arc::new(MemoryTelemetryStore::new()),
    };

    let revocations: Arc<dyn RevocationStore> = match &cfg.database_url {
        Some(url) => Arc::new(PostgresRevocationStore::new(url)?),
        None => Arc::new(MemoryRevocationStore::new()),
    };

    // Validate operator-configured endpoints at startup (fail closed) and, when
    // EGRESS_ALLOWLIST is set, require every configured endpoint to be allowed.
    let rpc_policy = crate::netguard::RpcPolicy::from_env();
    let egress = Arc::new(crate::netguard::EgressGuard::from_env());
    if let Some(anchor) = &cfg.anchor {
        // The operator's anchor RPC is trusted config (local nodes/anvil are legitimate), so
        // only its shape is checked here. Private-range rules apply to *tenant* target URLs
        // via `RpcPolicy` in `set_anchor_target`.
        crate::netguard::validate_endpoint(&anchor.rpc_url, "ANCHOR rpc_url")?;
        egress.check(&anchor.rpc_url)?;
    }
    if let Some(aws) = &cfg.aws {
        for (label, endpoint) in [
            ("AWS_STS_ENDPOINT", aws.endpoint_override.as_deref()),
            ("AWS_IAM_ENDPOINT", aws.iam_endpoint_override.as_deref()),
        ] {
            if let Some(url) = endpoint {
                crate::netguard::validate_endpoint(url, label)?;
                egress.check(url)?;
            }
        }
    }
    if let Some(github) = &cfg.github {
        crate::netguard::validate_endpoint(&github.api_base, "GITHUB_API_BASE")?;
        egress.check(&github.api_base)?;
    }
    if let Some(stripe) = &cfg.stripe {
        crate::netguard::validate_endpoint(&stripe.api_base, "STRIPE_API_BASE")?;
        egress.check(&stripe.api_base)?;
    }
    if let Some(hook) = &cfg.alert_webhook_url {
        crate::netguard::validate_endpoint(hook, "ALERT_WEBHOOK_URL")?;
        egress.check(hook)?;
    }
    if let Some(kms) = &cfg.kms_signer_url {
        crate::netguard::validate_endpoint(kms, "KMS_SIGNER_URL")?;
        egress.check(kms)?;
    }

    let rate_limiter: Arc<dyn crate::ratelimit::RateLimiter> = match &cfg.redis_url {
        Some(url) => Arc::new(crate::ratelimit::RedisRateLimiter::connect(url).await?),
        None => Arc::new(crate::ratelimit::MemoryRateLimiter::new()),
    };

    let anchor = match &cfg.anchor {
        Some(anchor) => {
            let backend: Option<Arc<dyn DigestSigner>> = if let Some(url) = &cfg.kms_signer_url {
                Some(Arc::new(HttpKmsSigner::new(
                    url,
                    cfg.kms_signer_address.as_deref().unwrap_or_default(),
                )))
            } else {
                match &anchor.private_key {
                    Some(key) => Some(Arc::new(LocalSigner::from_hex(key)?)),
                    None => {
                        tracing::warn!(
                            "RPC_URL/RECEIPT_ANCHOR_ADDRESS set but no ANCHOR_PK or KMS_SIGNER_URL; \
                             on-chain anchoring disabled"
                        );
                        None
                    }
                }
            };
            backend
                .map(|b| {
                    AnchorSubmitter::with_backend(&anchor.rpc_url, b, &anchor.contract)
                        .map(Arc::new)
                })
                .transpose()?
        }
        None => None,
    };

    let (anchors, anchor_targets): (Arc<dyn AnchorStore>, Arc<dyn AnchorTargetStore>) =
        match &cfg.database_url {
            Some(url) => {
                let pg: Arc<PostgresAnchoring> = Arc::new(PostgresAnchoring::new(url)?);
                (pg.clone(), pg)
            }
            None => (
                Arc::new(MemoryAnchorStore::new()),
                Arc::new(MemoryAnchorTargetStore::new()),
            ),
        };

    Ok(Arc::new(AuthorizeService {
        policies,
        issuers: Arc::new(issuers),
        signer,
        authority,
        chain,
        telemetry,
        revocations,
        http: crate::netguard::outbound_client(),
        anchor,
        anchors,
        anchor_targets,
        rpc_policy: Arc::new(rpc_policy),
        egress,
        rate_limiter,
        agent_rate_limit_per_min: cfg.agent_rate_limit_per_min,
        secrets,
        retention_days: cfg.retention_days,
        anchor_confirmations: cfg.anchor_confirmations,
        anchor_reorg_grace_secs: cfg.anchor_reorg_grace_secs,
        default_ttl_seconds: cfg
            .default_credential_ttl_seconds
            .clamp(1, cfg.max_credential_ttl_seconds.max(1)),
        max_ttl_seconds: cfg.max_credential_ttl_seconds.max(1),
        signing_key_history: cfg.signing_key_history.clone(),
        anchor_gap_threshold: cfg.anchor_gap_threshold,
        ledger_retention_days: cfg.ledger_retention_days,
        archive_dir: cfg.archive_dir.clone(),
        archive_interval_secs: cfg.archive_interval_secs,
        archive_replica_dir: cfg.archive_replica_dir.clone(),
        archive_retention_days: cfg.archive_retention_days,
        alert_webhook_url: cfg.alert_webhook_url.clone(),
        alert_webhook_token: cfg.alert_webhook_token.clone(),
        alert_repeat_secs: cfg.alert_repeat_secs,
        alert_retry_secs: cfg.alert_retry_secs,
        tool_pins: {
            let store: Arc<dyn crate::tool_pins::ToolPinStore> = match &cfg.database_url {
                Some(url) => Arc::new(crate::tool_pins_pg::PostgresToolPins::new(url)?),
                None => Arc::new(crate::tool_pins::MemoryToolPins::new()),
            };
            store
        },
        remediation_policies: {
            let store: Arc<dyn crate::remediation::RemediationPolicyStore> = match &cfg.database_url
            {
                Some(url) => Arc::new(crate::remediation_pg::PostgresRemediationPolicies::new(
                    url,
                )?),
                None => Arc::new(crate::remediation::MemoryRemediationPolicies::new()),
            };
            store
        },
        quota: Arc::new(crate::quota::QuotaManager::new(
            cfg.provider_max_inflight,
            cfg.provider_max_inflight_per_tenant,
        )),
        chain_checkpoints: {
            let store: Arc<dyn crate::chain_checkpoints::ChainCheckpointStore> =
                match &cfg.database_url {
                    Some(url) => Arc::new(
                        crate::chain_checkpoints_pg::PostgresChainCheckpoints::new(url)?,
                    ),
                    None => Arc::new(crate::chain_checkpoints::MemoryChainCheckpoints::new()),
                };
            store
        },
        key_events: {
            let store: Arc<dyn crate::key_events::KeyEventStore> = match &cfg.database_url {
                Some(url) => Arc::new(crate::key_events_pg::PostgresKeyEvents::new(url)?),
                None => Arc::new(crate::key_events::MemoryKeyEvents::new()),
            };
            store
        },
        alert_acks: {
            let store: Arc<dyn crate::alert_acks::AlertAckStore> = match &cfg.database_url {
                Some(url) => Arc::new(crate::alert_acks_pg::PostgresAlertAcks::new(url)?),
                None => Arc::new(crate::alert_acks::MemoryAlertAcks::new()),
            };
            store
        },
        alert_router: {
            let store: Arc<dyn crate::alerts::AlertTargetStore> = match &cfg.database_url {
                Some(url) => Arc::new(crate::alerts_pg::PostgresAlertTargets::new(url)?),
                None => Arc::new(crate::alerts::MemoryAlertTargetStore::new()),
            };
            Arc::new(
                crate::alerts::AlertRouter::new(
                    store,
                    cfg.alert_webhook_url.clone(),
                    cfg.alert_webhook_token.clone(),
                )
                .with_auto_ack(cfg.alert_auto_ack_below),
            )
        },
        key_expiry_alert_days: cfg.key_expiry_alert_days,
        key_rotation_max_age_hours: cfg.key_rotation_max_age_hours,
        gap_alerts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        tool_rate_limits: cfg.tool_rate_limits.clone(),
        demo_policy,
    }))
}

/// Build the full HTTP application state (service + API-key store).
pub async fn build_state(cfg: &BrokerConfig) -> Result<Arc<AppState>, BrokerError> {
    let service = build_service(cfg).await?;

    let base_keys: Arc<dyn ApiKeyStore> = match &cfg.database_url {
        Some(url) => Arc::new(PostgresApiKeyStore::new(url)?),
        None => Arc::new(MemoryApiKeyStore::new()),
    };
    let cache: Arc<dyn Cache> = match &cfg.redis_url {
        Some(url) => Arc::new(RedisCache::connect(url).await?),
        None => Arc::new(MemoryCache::new()),
    };
    let keys: Arc<dyn ApiKeyStore> = Arc::new(CachedApiKeyStore::new(base_keys, cache.clone(), 60));

    Ok(Arc::new(AppState {
        service: service.clone(),
        keys,
        demo_allow: cfg.demo_allow,
        admin_token: cfg.admin_token.clone(),
        rate_limit_per_min: cfg.rate_limit_per_min,
        public_rate_limit_per_min: cfg.public_rate_limit_per_min,
        rate_limiter: service.rate_limiter.clone(),
        trusted_proxies: Arc::new(crate::clientip::TrustedProxies::from_env()),
        cache: cache.clone(),
        chain_read_limit: crate::http::chain_read_limit(),
        heavy_route_rate_limit: crate::http::heavy_route_rate_limit(),
    }))
}
