//! The authorize and record paths: evaluate policy, broker a credential, sign a receipt,
//! and extend the per-agent receipt chain with outcomes.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::anchoring::{AnchorRecord, AnchorStore, AnchorTarget, AnchorTargetStore, ClaimOutcome};
use crate::canonical;
use crate::chain::{AppendOutcome, ChainEntry, ChainStore};
use crate::error::BrokerError;
use crate::eth::AnchorSubmitter;
use crate::issuers::{
    provider_for, resource_from_tool, CredentialMaterial, EphemeralCredential, IssueRequest,
    IssuerRegistry,
};
use crate::merkle::{self, AnchorBatch};
use crate::netguard::RpcPolicy;
use crate::policy::{evaluate, Policy, PolicyContext, PolicyStore};
use crate::proxy::{ProxyRequest, ProxyResponse};
use crate::receipt::{
    new_receipt, restamp, AgentRef, AttestationRef, AuthorizationRef, CallRef, CredentialRef,
    GrantReceipt, GrantRef, IntentRef, OutcomeRef, PolicyRef, PrincipalRef, ReceiptSigner,
};
use crate::revocation::{provider_capability, RevocationEvent, RevocationStore};
use crate::secrets::{is_encrypted, Envelope};
use crate::telemetry::{observe_fields, Observation, ProposedPolicy, TelemetryStore};

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeRequest {
    pub agent_id: String,
    pub user_id: String,
    pub tool: String,
    pub intent: String,
    #[serde(default)]
    pub args: serde_json::Value,
    /// Hash of the tool definition the client was given (`keccak256(canonical JSON)`).
    /// Required for pinned tools so a silent redefinition (rug pull) is refused.
    #[serde(
        default,
        rename = "toolSchemaHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_schema_hash: Option<String>,
    /// Delegating human/organization authority. When omitted, the broker binds the `user_id`
    /// as a caller-asserted principal so existing clients keep working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalInput>,
    /// HS256 JWT minted by the tenant backend. When present, the broker verifies it and
    /// overrides the caller-asserted principal with the token subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_token: Option<String>,
    /// Optional agent version/model/operator metadata for the v2 record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_meta: Option<AgentInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalInput {
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
    pub authority_ref: String,
    pub authority_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordRequest {
    pub agent_id: String,
    /// The `receiptId` returned by `/v1/authorize` (i.e. the authorization receipt's payload hash).
    pub receipt_id: String,
    pub result_hash: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeResponse {
    pub decision: Decision,
    pub reason: String,
    pub credential: Option<EphemeralCredential>,
    pub receipt: GrantReceipt,
    /// Identifies the receipt for later `/v1/record` calls.
    pub receipt_id: String,
    /// Stable id shared by the authorization record and its outcome record (v2+).
    pub action_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordResponse {
    pub status: String,
    pub receipt_id: String,
    pub receipt: GrantReceipt,
    pub chain_length: usize,
    /// True when an outcome for this authorization receipt was already recorded.
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeOutcome {
    pub event: RevocationEvent,
    pub provider: Option<String>,
    pub capability: Option<String>,
    pub grant_revoked: Option<bool>,
    pub credential_revoked: Option<bool>,
}

fn agent_chain_lock(tenant: &str, agent: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    let locks = LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.len() >= 10_000 {
        guard.retain(|_, lock| Arc::strong_count(lock) > 1);
    }
    guard
        .entry(format!("{tenant}\0{agent}"))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

#[derive(Clone)]
pub struct AuthorizeService {
    pub policies: Arc<dyn PolicyStore>,
    pub issuers: Arc<IssuerRegistry>,
    pub signer: Arc<ReceiptSigner>,
    pub chain: Arc<dyn ChainStore>,
    pub telemetry: Arc<dyn TelemetryStore>,
    pub revocations: Arc<dyn RevocationStore>,
    pub http: reqwest::Client,
    /// Per-tenant alert routing (falls back to the operator-wide webhook).
    pub alert_router: Arc<crate::alerts::AlertRouter>,
    /// Alert acknowledgements (suppress repeats until the condition worsens).
    pub alert_acks: Arc<dyn crate::alert_acks::AlertAckStore>,
    /// Hash-linked key-event ledger.
    pub key_events: Arc<dyn crate::key_events::KeyEventStore>,
    /// Provider in-flight reservations (global + per tenant).
    pub quota: Arc<crate::quota::QuotaManager>,
    /// Per-tenant auto-remediation policy (narrow new/widened keys to a template).
    pub remediation_policies: Arc<dyn crate::remediation::RemediationPolicyStore>,
    /// Approved tool-definition pins (rug-pull defense).
    pub tool_pins: Arc<dyn crate::tool_pins::ToolPinStore>,
    /// Per-agent chain checkpoints (head/count at archive time).
    pub chain_checkpoints: Arc<dyn crate::chain_checkpoints::ChainCheckpointStore>,
    /// Days before expiry at which API keys are reported/altered (0 disables).
    pub key_expiry_alert_days: u64,
    /// Hours after which an un-rotated key is reported (None disables; 0 = always due).
    pub key_rotation_max_age_hours: Option<u64>,
    pub anchor: Option<Arc<AnchorSubmitter>>,
    pub anchors: Arc<dyn AnchorStore>,
    pub anchor_targets: Arc<dyn AnchorTargetStore>,
    /// Envelope cipher for secrets persisted by the broker (tenant anchor keys).
    pub secrets: Option<Arc<Envelope>>,
    /// Egress policy for tenant-supplied anchor RPC URLs.
    pub rpc_policy: Arc<RpcPolicy>,
    /// Optional strict egress allowlist for outbound calls.
    pub egress: Arc<crate::netguard::EgressGuard>,
    /// Shared rate limiter (tenant + agent budgets).
    pub rate_limiter: Arc<dyn crate::ratelimit::RateLimiter>,
    /// Per-agent request budget (requests/minute). None disables.
    pub agent_rate_limit_per_min: Option<u32>,
    /// Per-resource budgets (`resource=per_minute`).
    pub tool_rate_limits: Vec<(String, u32)>,
    /// Hard ceiling on credential lifetime (seconds).
    pub max_ttl_seconds: u32,
    /// Historical broker signer addresses (for verifying pre-rotation receipts).
    pub signing_key_history: Vec<String>,
    /// Authority-token verifier: keyring, issuer/audience, replay cache, required-token mode.
    pub authority: crate::authority::AuthorityVerifier,
    /// Warn when a live chain has grown this many receipts past its last anchor.
    pub anchor_gap_threshold: u64,
    /// Days after which key-event ledger entries are compacted (0 keeps everything).
    pub ledger_retention_days: u64,
    /// Directory for scheduled tenant archives (tar.gz). None disables.
    pub archive_dir: Option<String>,
    /// Seconds between scheduled tenant archives.
    pub archive_interval_secs: u64,
    /// Second location each archive is copied to (digest-verified). None disables.
    pub archive_replica_dir: Option<String>,
    /// Days after which evidence files are pruned (0 keeps everything).
    pub archive_retention_days: u64,
    /// Webhook notified when a chain crosses the anchor gap threshold.
    pub alert_webhook_url: Option<String>,
    /// Shared secret sent as `x-tessera-alert-token`.
    pub alert_webhook_token: Option<String>,
    /// Minimum seconds between repeat alerts for the same (tenant, agent).
    pub alert_repeat_secs: u64,
    /// Seconds before retrying a *failed* alert delivery (shorter than the repeat window).
    pub alert_retry_secs: u64,
    /// Next allowed alert time per (tenant, agent).
    pub gap_alerts: Arc<tokio::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    /// Retention window (days); 0 disables the sweep.
    pub retention_days: u64,
    /// Blocks on top of an anchor before it is final.
    pub anchor_confirmations: u64,
    /// Grace period (seconds) before an unmined anchor is treated as reorged.
    pub anchor_reorg_grace_secs: u64,
    pub default_ttl_seconds: u32,
    pub demo_policy: Option<Policy>,
}

impl AuthorizeService {
    /// Create/migrate every persistent store. Idempotent; call once at startup.
    pub async fn migrate(&self) -> Result<(), BrokerError> {
        self.chain.migrate().await?;
        self.policies.migrate().await?;
        self.telemetry.migrate().await?;
        self.revocations.migrate().await?;
        self.anchors.migrate().await?;
        self.anchor_targets.migrate().await?;
        self.key_events.migrate().await?;
        self.alert_acks.migrate().await?;
        self.alert_router.migrate().await?;
        self.remediation_policies.migrate().await?;
        self.chain_checkpoints.migrate().await?;
        self.tool_pins.migrate().await?;
        Ok(())
    }

    /// Evaluate policy and, if allowed, broker an ephemeral credential. Always returns a
    /// signed receipt (allow or deny), appended to the agent's chain.
    pub async fn authorize(
        &self,
        tenant: &str,
        req: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, BrokerError> {
        if !crate::auth::valid_agent_id(&req.agent_id) {
            return Err(BrokerError::Invalid(format!(
                "invalid agentId '{}': use 1-128 characters of [A-Za-z0-9._:@-]",
                req.agent_id
            )));
        }
        validate_authorize_input(&req)?;
        // Tool-definition pinning: an approved tool that changed underneath us is refused
        // until a human re-approves it (MCP rug-pull / tool-poisoning defense).
        if let Some(pin) = self.tool_pins.get(tenant, &req.tool).await? {
            match req.tool_schema_hash.as_deref() {
                Some(hash) if hash.eq_ignore_ascii_case(&pin.definition_hash) => {}
                Some(received) => {
                    crate::metrics::tool_drift_denial();
                    if let Err(e) = self
                        .append_ledger_event(
                            tenant,
                            "tool.drift",
                            &req.tool,
                            "",
                            "",
                            serde_json::json!({
                                "tool": req.tool,
                                "expected": pin.definition_hash,
                                "received": received,
                                "agentId": req.agent_id,
                            }),
                        )
                        .await
                    {
                        tracing::warn!(tenant = %tenant, tool = %req.tool, "tool drift audit failed: {e}");
                    }
                    return Err(BrokerError::Denied(format!(
                        "tool '{}' definition changed since approval (possible rug pull);                          re-approve the tool before calling it",
                        req.tool
                    )));
                }
                None => {
                    return Err(BrokerError::Denied(format!(
                        "tool '{}' is pinned; toolSchemaHash is required",
                        req.tool
                    )));
                }
            }
        }

        let resource = resource_from_tool(&req.tool);
        let args = if req.args.is_null() {
            serde_json::json!({})
        } else {
            req.args.clone()
        };
        if args.as_object().is_none() {
            return Err(BrokerError::Invalid("args must be a JSON object".into()));
        }
        if let Some((_, per_minute)) = self
            .tool_rate_limits
            .iter()
            .find(|(configured, _)| configured == &resource)
        {
            let key = format!("tool:{tenant}:{resource}");
            if !self.rate_limiter.allow_per_minute(&key, *per_minute).await {
                crate::metrics::authorize_deny();
                crate::metrics::throttled();
                return Err(BrokerError::Throttled(format!(
                    "resource '{resource}' exceeded its rate limit"
                )));
            }
        }

        if let Some(per_minute) = self.agent_rate_limit_per_min {
            let key = format!("agent:{tenant}:{}", req.agent_id);
            if !self.rate_limiter.allow_per_minute(&key, per_minute).await {
                crate::metrics::authorize_deny();
                crate::metrics::throttled();
                return Err(BrokerError::Throttled(format!(
                    "agent '{}' exceeded its rate limit",
                    req.agent_id
                )));
            }
        }

        let args_hash = canonical::hash_json(&args);
        let intent_hash = canonical::keccak256_str(&req.intent);
        let principal = self
            .authority
            .verify(
                req.authority_token.as_deref(),
                tenant,
                &req.agent_id,
                req.principal
                    .as_ref()
                    .map(|principal| principal.principal_id.as_str()),
                req.principal
                    .as_ref()
                    .and_then(|principal| principal.principal_type.as_deref()),
            )
            .await?
            .unwrap_or_else(|| principal_from(&req));
        // The verified token subject (or the caller-asserted principal when no token is
        // configured) is the identity policy evaluates and the receipt binds as `user`.
        let effective_user_id = principal.principal_id.clone();

        let mut policies = self.policies.policies_for(tenant).await?;
        if policies.is_empty() {
            if let Some(p) = &self.demo_policy {
                policies.push(p.clone());
            }
        }

        let ctx = PolicyContext {
            agent_id: req.agent_id.clone(),
            user_id: effective_user_id.clone(),
            resource: resource.clone(),
            args: args.clone(),
        };
        let decision = if self.revocations.is_revoked(tenant, &req.agent_id).await? {
            crate::policy::PolicyResult::deny("agent revoked", &resource)
        } else {
            evaluate(&policies, &ctx)
        };
        if decision.allow {
            // Policy-level budgets (narrowing only; global budgets were checked above).
            if let Some((_, per_minute)) = decision
                .limits
                .tool_rate_limits
                .iter()
                .find(|(configured, _)| configured == &resource)
            {
                let key = format!("policy-tool:{tenant}:{resource}");
                if !self.rate_limiter.allow_per_minute(&key, *per_minute).await {
                    crate::metrics::authorize_deny();
                    crate::metrics::throttled();
                    return Err(BrokerError::Throttled(format!(
                        "resource '{resource}' exceeded its policy rate limit"
                    )));
                }
            }
            if let Some(per_minute) = decision.limits.agent_rate_limit_per_min {
                let key = format!("policy-agent:{tenant}:{}", req.agent_id);
                if !self.rate_limiter.allow_per_minute(&key, per_minute).await {
                    crate::metrics::authorize_deny();
                    crate::metrics::throttled();
                    return Err(BrokerError::Throttled(format!(
                        "agent '{}' exceeded its policy rate limit",
                        req.agent_id
                    )));
                }
            }
            crate::metrics::authorize_allow();
        } else {
            crate::metrics::authorize_deny();
        }

        let action_id = uuid::Uuid::new_v4().to_string();
        let agent_meta = agent_meta_from(&req);
        let intent_ref = IntentRef {
            intent_hash: intent_hash.clone(),
            requested_scopes: req.requested_scopes.clone().unwrap_or_default(),
            risk_class: req.risk_class.clone(),
            declared_purpose: req.declared_purpose.clone(),
        };
        let policy_ref = policy_ref(
            &decision,
            &req.agent_id,
            &effective_user_id,
            &resource,
            &args_hash,
        );

        if !decision.allow {
            let mut receipt = new_receipt(
                tenant,
                &req.agent_id,
                &effective_user_id,
                intent_hash,
                AuthorizationRef {
                    decision: "deny".into(),
                    policy: decision.policy_id,
                    policy_version: decision.policy_version,
                    resource: resource.clone(),
                    anomaly_score: decision.anomaly_score,
                    policy_hash: Some(policy_ref.policy_hash.clone()),
                },
                CallRef {
                    tool: req.tool.clone(),
                    args_hash,
                    result_hash: None,
                    tool_hash: req.tool_schema_hash.clone(),
                },
                GrantRef {
                    provider: provider_for(&resource).to_string(),
                    ttl_s: 0,
                    single_use: true,
                    status: "denied".into(),
                },
            );
            receipt.v = 2;
            receipt.action_id = Some(action_id.clone());
            receipt.principal = Some(principal);
            receipt.agent_meta = Some(agent_meta);
            receipt.intent = Some(intent_ref);
            receipt.policy = Some(policy_ref);
            receipt.attestation = Some(attestation_ref(&self.signer));
            if let Some(attestation) = &mut receipt.attestation {
                attestation.timestamp = Some(receipt.ts.clone());
            }
            crate::receipt::validate_v2(&receipt)?;
            let entry = self.append(tenant, &req.agent_id, receipt).await?;
            return Ok(AuthorizeResponse {
                decision: Decision::Deny,
                reason: decision.reason,
                credential: None,
                receipt: entry.receipt,
                receipt_id: entry.payload_hash,
                action_id,
            });
        }

        let issue_req = IssueRequest {
            tenant: tenant.to_string(),
            agent_id: req.agent_id.clone(),
            user_id: effective_user_id.clone(),
            resource: resource.clone(),
            scope: vec![],
            // A policy may shorten, never lengthen, the credential lifetime.
            ttl_seconds: self
                .default_ttl_seconds
                .min(decision.limits.max_ttl_seconds.unwrap_or(u32::MAX))
                .clamp(1, self.max_ttl_seconds.max(1)),
            args_hash: args_hash.clone(),
            args,
        };
        let provider = provider_for(&resource);
        let mut credential = {
            let _permit = self.quota.acquire(provider, tenant)?;
            self.issuers.exchange(&resource, &issue_req).await?
        };
        if credential.issuance_id.is_none() {
            credential.issuance_id = Some(match &credential.material {
                CredentialMaterial::Grant { grant_id, .. } => grant_id.clone(),
                CredentialMaterial::AwsSts { access_key_id, .. } => access_key_id.clone(),
                CredentialMaterial::Bearer { .. } => credential
                    .reference
                    .clone()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            });
        }
        crate::metrics::credential_issued();

        let credential_record = credential_ref(&credential, &issue_req.scope);
        let mut receipt = new_receipt(
            tenant,
            &req.agent_id,
            &effective_user_id,
            intent_hash,
            AuthorizationRef {
                decision: "allow".into(),
                policy: decision.policy_id,
                policy_version: decision.policy_version,
                resource: resource.clone(),
                anomaly_score: decision.anomaly_score,
                policy_hash: Some(policy_ref.policy_hash.clone()),
            },
            CallRef {
                tool: req.tool.clone(),
                args_hash,
                result_hash: None,
                tool_hash: req.tool_schema_hash.clone(),
            },
            GrantRef {
                provider: credential.provider.clone(),
                ttl_s: credential.ttl_seconds,
                single_use: credential.single_use,
                status: "issued".into(),
            },
        );
        receipt.v = 2;
        receipt.action_id = Some(action_id.clone());
        receipt.principal = Some(principal);
        receipt.agent_meta = Some(agent_meta);
        receipt.intent = Some(intent_ref);
        receipt.policy = Some(policy_ref);
        receipt.credential = Some(credential_record);
        receipt.attestation = Some(attestation_ref(&self.signer));
        if let Some(attestation) = &mut receipt.attestation {
            attestation.timestamp = Some(receipt.ts.clone());
        }
        crate::receipt::validate_v2(&receipt)?;
        let entry = self.append(tenant, &req.agent_id, receipt).await?;

        // Bind a broker-held grant to this authorization so the proxy can append the
        // outcome it observes, even after later actions for the same agent.
        if let CredentialMaterial::Grant { grant_id, .. } = &credential.material {
            if let Err(e) = self
                .issuers
                .bind_grant(
                    tenant,
                    grant_id,
                    &entry.payload_hash,
                    &action_id,
                    &req.agent_id,
                )
                .await
            {
                tracing::warn!(tenant = %tenant, grant = %grant_id, "grant binding failed: {e}");
            }
        }

        // Record the argument shape for auto-policy proposals (best effort).
        let mut fields = Vec::new();
        observe_fields(&issue_req.args, &mut fields);
        let observation = Observation {
            tenant: tenant.to_string(),
            resource: resource.clone(),
            fields,
        };
        if let Err(e) = self.telemetry.record(&observation).await {
            tracing::warn!("telemetry record failed: {e}");
        }

        Ok(AuthorizeResponse {
            decision: Decision::Allow,
            reason: decision.reason,
            credential: Some(credential),
            receipt: entry.receipt,
            receipt_id: entry.payload_hash,
            action_id,
        })
    }

    /// Record the outcome of an authorized call, appending a linked receipt to the chain.
    /// Idempotent: recording the same authorization receipt twice returns the existing
    /// outcome instead of appending a duplicate (re-checked on every append retry).
    pub async fn record(
        &self,
        tenant: &str,
        req: RecordRequest,
    ) -> Result<RecordResponse, BrokerError> {
        self.record_with_source(tenant, req, "agent_reported").await
    }

    async fn record_with_source(
        &self,
        tenant: &str,
        req: RecordRequest,
        outcome_source: &str,
    ) -> Result<RecordResponse, BrokerError> {
        if !crate::auth::valid_agent_id(&req.agent_id) {
            return Err(BrokerError::Invalid("invalid agentId".into()));
        }
        validate_record_input(&req)?;
        let outcome_status = normalize_outcome_status(req.status.as_deref());
        let chain_lock = agent_chain_lock(tenant, &req.agent_id);
        let _chain_guard = chain_lock.lock().await;
        for attempt in 0..64 {
            // Indexed lookups: the chain is never materialized, so recording an outcome stays
            // cheap however long the chain grows.
            let authorization = self
                .chain
                .find(tenant, &req.agent_id, &req.receipt_id)
                .await?
                .ok_or_else(|| {
                    BrokerError::NotFound(format!(
                        "receipt {} not found for agent {}",
                        req.receipt_id, req.agent_id
                    ))
                })?;

            if authorization.authorization.decision != "allow" {
                return Err(BrokerError::Invalid(
                    "authorization was denied; there is no outcome to record".into(),
                ));
            }
            if outcome_source == "agent_reported"
                && authorization
                    .credential
                    .as_ref()
                    .is_some_and(|credential| credential.credential_type == "broker_grant")
            {
                return Err(BrokerError::Invalid(
                    "broker-held grants must record their outcome through /v1/proxy".into(),
                ));
            }

            if let Some(existing) = self
                .chain
                .find_outcome_for_authorization(tenant, &req.agent_id, &req.receipt_id)
                .await?
            {
                if existing.receipt.call.result_hash.as_deref() != Some(req.result_hash.as_str()) {
                    return Err(BrokerError::Invalid(
                        "authorization already has a different recorded outcome".into(),
                    ));
                }
                if let Some(recorded) = &existing.receipt.outcome {
                    if recorded.status != outcome_status {
                        return Err(BrokerError::Invalid(
                            "authorization already has a different outcome status".into(),
                        ));
                    }
                }
                return Ok(RecordResponse {
                    status: "duplicate".to_string(),
                    receipt_id: existing.payload_hash.clone(),
                    receipt: existing.receipt.clone(),
                    chain_length: self.chain.len(tenant, &req.agent_id).await?,
                    duplicate: true,
                });
            }

            // Outcomes may arrive after later authorizations for the same agent. Link
            // them to their authorization by id and to the chain by the current head.
            let head = self.chain.head_hash(tenant, &req.agent_id).await?;

            let mut receipt = authorization;
            receipt.call.result_hash = Some(req.result_hash.clone());
            receipt.grant.status = match outcome_status.as_str() {
                "denied" => "denied",
                _ => "used",
            }
            .to_string();
            if receipt.v >= 2 {
                receipt.outcome = Some(OutcomeRef {
                    status: outcome_status.clone(),
                    source: Some(outcome_source.to_string()),
                    result_hash: Some(req.result_hash.clone()),
                    error_class: req.error_class.clone(),
                    external_ref: req.external_ref.clone(),
                    completed_at: req.completed_at.clone().unwrap_or_else(now_ts),
                });
            }
            restamp(&mut receipt);
            if receipt.v >= 2 {
                receipt.attestation = Some(attestation_ref(&self.signer));
                if let Some(attestation) = &mut receipt.attestation {
                    attestation.timestamp = Some(receipt.ts.clone());
                }
            }
            // The outcome links explicitly to its authorization receipt. `prev` is the
            // current chain head so an outcome remains recordable after later actions.
            if receipt.v >= 2 {
                receipt.authorization_receipt_id = Some(req.receipt_id.clone());
            }
            receipt.prev = head;
            crate::receipt::validate_v2(&receipt)?;
            self.signer.sign(&mut receipt).await?;
            let entry = ChainEntry {
                payload_hash: crate::receipt::payload_hash_hex(&receipt)?,
                receipt,
            };

            if self
                .chain
                .append(tenant, &req.agent_id, entry.clone())
                .await?
                == AppendOutcome::Appended
            {
                let chain_length = self.chain.len(tenant, &req.agent_id).await?;
                return Ok(RecordResponse {
                    status: "recorded".to_string(),
                    receipt_id: entry.payload_hash,
                    receipt: entry.receipt,
                    chain_length,
                    duplicate: false,
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(1 + (attempt % 5) as u64)).await;
        }
        Err(BrokerError::Internal(
            "receipt chain append contention".into(),
        ))
    }

    /// Verify signatures and links across an agent's whole chain.
    pub async fn verify_chain(&self, tenant: &str, agent: &str) -> Result<bool, BrokerError> {
        let chain = self.chain.chain(tenant, agent).await?;
        let address = self.signer.address_hex();
        let expected = if self.signer.is_deterministic() {
            Some(address.as_str())
        } else {
            None
        };
        crate::chain::verify_chain(&chain, &self.signer, expected)
    }

    /// Redeem a broker-held grant and forward exactly one request to the provider.
    pub async fn proxy(
        &self,
        tenant: &str,
        req: ProxyRequest,
    ) -> Result<ProxyResponse, BrokerError> {
        self.proxy_scoped(tenant, req, None).await
    }

    /// Proxy a granted call, enforcing the caller's API-key scope against the grant's
    /// resource so a narrow key cannot redeem a grant issued for something else.
    pub async fn proxy_scoped(
        &self,
        tenant: &str,
        req: ProxyRequest,
        scope: Option<&crate::auth::KeyScope>,
    ) -> Result<ProxyResponse, BrokerError> {
        crate::metrics::proxy_call();
        if self.revocations.is_revoked(tenant, &req.grant_id).await? {
            crate::metrics::proxy_denied();
            return Err(BrokerError::Denied("grant revoked".into()));
        }
        // Check the key scope *before* redeeming: a denied request must not consume the
        // single-use grant.
        if let Some(scope) = scope {
            if !scope.allows_proxy_path(&req.path) {
                crate::metrics::proxy_denied();
                return Err(BrokerError::Denied(format!(
                    "API key is not scoped for upstream path '{}'",
                    req.path
                )));
            }
            if let Ok(Some(resource)) = self.issuers.grant_resource(tenant, &req.grant_id).await {
                if !resource.is_empty() && !scope.allows_resource(&resource) {
                    crate::metrics::proxy_denied();
                    return Err(BrokerError::Denied(format!(
                        "API key is not scoped for resource '{resource}'"
                    )));
                }
            }
        }
        let redeemed = self
            .issuers
            .redeem(tenant, &req.grant_id, &req.args_hash)
            .await?;
        if let Some(scope) = scope {
            if !redeemed.resource.is_empty() && !scope.allows_resource(&redeemed.resource) {
                crate::metrics::proxy_denied();
                return Err(BrokerError::Denied(format!(
                    "API key is not scoped for resource '{}'",
                    redeemed.resource
                )));
            }
        }
        self.egress.check_resolved(&redeemed.spec.base_url).await?;
        // Reserve provider capacity for the duration of the upstream call.
        let provider = crate::issuers::grant_provider(&req.grant_id).unwrap_or("provider");
        let _permit = self.quota.acquire(provider, tenant)?;

        let authorization_receipt_id = redeemed.authorization_receipt_id.clone();
        let action_id = redeemed.action_id.clone();
        let agent_id = redeemed.agent_id.clone();
        let mut response =
            match crate::proxy::forward(&self.http, &redeemed.spec, &redeemed.secret, &req).await {
                Ok(response) => response,
                Err(error) => {
                    self.record_proxy_outcome(
                        tenant,
                        authorization_receipt_id.as_deref(),
                        action_id.as_deref(),
                        agent_id.as_deref(),
                        "failure",
                        &canonical::hash_json(&serde_json::json!({
                            "error": error.to_string()
                        })),
                        "proxy_transport_error",
                    )
                    .await;
                    return Err(error);
                }
            };

        let result_hash = canonical::hash_json(&serde_json::json!({
            "status": response.status,
            "contentType": response.content_type,
            "body": response.body,
        }));
        let outcome_status = if (200..300).contains(&response.status) {
            "success"
        } else if (400..600).contains(&response.status) {
            "failure"
        } else {
            "unknown"
        };
        let (outcome_receipt_id, outcome_recorded, outcome_receipt) = self
            .record_proxy_outcome(
                tenant,
                authorization_receipt_id.as_deref(),
                action_id.as_deref(),
                agent_id.as_deref(),
                outcome_status,
                &result_hash,
                if outcome_status == "failure" {
                    "upstream_http_error"
                } else {
                    ""
                },
            )
            .await;
        response.action_id = action_id;
        response.authorization_receipt_id = authorization_receipt_id;
        response.outcome_receipt_id = outcome_receipt_id;
        response.outcome_receipt = outcome_receipt;
        response.outcome_recorded = outcome_recorded;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_proxy_outcome(
        &self,
        tenant: &str,
        authorization_receipt_id: Option<&str>,
        action_id: Option<&str>,
        agent_id: Option<&str>,
        status: &str,
        result_hash: &str,
        error_class: &str,
    ) -> (Option<String>, bool, Option<GrantReceipt>) {
        let (Some(authorization_receipt_id), Some(agent_id)) = (authorization_receipt_id, agent_id)
        else {
            tracing::warn!(
                tenant = %tenant,
                action = ?action_id,
                "proxy outcome not recorded: grant has no authorization binding"
            );
            return (None, false, None);
        };
        let request = RecordRequest {
            agent_id: agent_id.to_string(),
            receipt_id: authorization_receipt_id.to_string(),
            result_hash: result_hash.to_string(),
            status: Some(status.to_string()),
            error_class: (!error_class.is_empty()).then(|| error_class.to_string()),
            external_ref: None,
            completed_at: None,
        };
        match self
            .record_with_source(tenant, request, "broker_observed")
            .await
        {
            Ok(recorded) => (Some(recorded.receipt_id), true, Some(recorded.receipt)),
            Err(error) => {
                tracing::warn!(
                    tenant = %tenant,
                    action = ?action_id,
                    "proxy outcome record failed: {error}"
                );
                (None, false, None)
            }
        }
    }

    /// Every broker signer address a verifier should accept: the current key first, then
    /// any historical keys from previous rotations.
    pub fn accepted_signers(&self) -> Vec<String> {
        let mut signers = vec![self.signer.address_hex()];
        for historical in &self.signing_key_history {
            if !signers.iter().any(|s| s.eq_ignore_ascii_case(historical)) {
                signers.push(historical.clone());
            }
        }
        signers
    }

    /// Detect agents whose live chain has grown past their last live anchor.
    pub async fn anchor_gaps(&self, tenant: &str) -> Result<Vec<serde_json::Value>, BrokerError> {
        let mut agents = self.chain.agents_for_tenant(tenant).await?;
        agents.sort();
        let mut gaps = Vec::new();
        for agent in agents {
            let chain_length = self.chain.len(tenant, &agent).await? as u64;
            let latest = self
                .anchors
                .list(tenant)
                .await?
                .into_iter()
                .filter(|record| {
                    record.agent == agent
                        && matches!(
                            record.status.as_str(),
                            "submitted" | "confirmed" | "finalized"
                        )
                })
                .max_by_key(|record| record.count);
            let (last_count, last_status, last_at) = match &latest {
                Some(record) => (
                    record.count,
                    Some(record.status.clone()),
                    Some(record.created_at.clone()),
                ),
                None => (0, None, None),
            };
            let gap = chain_length.saturating_sub(last_count);
            if gap == 0 && latest.is_some() {
                continue;
            }
            gaps.push(serde_json::json!({
                "agent": agent,
                "chainLength": chain_length,
                "lastAnchoredCount": last_count,
                "gap": gap,
                "lastAnchorStatus": last_status,
                "lastAnchorAt": last_at,
            }));
        }
        gaps.sort_by(|a, b| {
            b["gap"]
                .as_u64()
                .cmp(&a["gap"].as_u64())
                .then_with(|| a["agent"].as_str().cmp(&b["agent"].as_str()))
        });
        Ok(gaps)
    }

    /// Force an anchor for up to `max_agents` agents whose gap is at/over
    /// `anchor_gap_threshold`. Claims keep this safe: a root already claimed is skipped.
    pub async fn heal_anchor_gaps(
        &self,
        tenant: &str,
        max_agents: usize,
    ) -> Result<Vec<String>, BrokerError> {
        if self.anchor_gap_threshold == 0 || self.anchor.is_none() {
            return Ok(Vec::new());
        }
        let mut healed = Vec::new();
        for gap in self.anchor_gaps(tenant).await? {
            if healed.len() >= max_agents {
                break;
            }
            let size = gap["gap"].as_u64().unwrap_or(0);
            if size < self.anchor_gap_threshold {
                continue;
            }
            let Some(agent) = gap["agent"].as_str() else {
                continue;
            };
            crate::metrics::anchor_gap_heal_attempt();
            match self.anchor_and_record(tenant, agent, true).await {
                Ok(Some(_)) => {
                    crate::metrics::anchor_gap_healed();
                    healed.push(agent.to_string());
                    tracing::info!(tenant = %tenant, agent = %agent, gap = size, "forced anchor for gap");
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(tenant = %tenant, agent = %agent, "gap anchor failed: {e}")
                }
            }
        }
        Ok(healed)
    }

    /// Validate a bundle and compare it against the local chain without writing anything.
    /// Returns the validated receipts plus a drift report.
    async fn inspect_import(
        &self,
        tenant: &str,
        bundle: &crate::export::ExportBundle,
    ) -> Result<(Vec<crate::chain::ChainEntry>, serde_json::Value), BrokerError> {
        if !bundle.manifest.tenant.eq(tenant) {
            return Err(BrokerError::Denied(
                "bundle belongs to a different tenant".into(),
            ));
        }
        if !crate::auth::valid_agent_id(&bundle.manifest.agent) {
            return Err(BrokerError::Invalid(
                "bundle manifest has an invalid agent id".into(),
            ));
        }
        if !bundle.verify()? {
            return Err(BrokerError::Invalid(
                "bundle failed verification (linkage, Merkle root, or signature)".into(),
            ));
        }
        let accepted = self.accepted_signers();
        let signer_accepted = accepted
            .iter()
            .any(|signer| signer.eq_ignore_ascii_case(&bundle.manifest.signer));
        if !signer_accepted {
            return Err(BrokerError::Denied(format!(
                "bundle signer {} is not an accepted broker signer",
                bundle.manifest.signer
            )));
        }
        if bundle.receipts.len() > crate::export::MAX_EXPORT_RECEIPTS {
            return Err(BrokerError::Invalid(format!(
                "too many receipts: {} (max {})",
                bundle.receipts.len(),
                crate::export::MAX_EXPORT_RECEIPTS
            )));
        }

        // Verify each receipt's own signature and stored payload hash: the bundle root proves
        // internal consistency, not per-receipt authenticity.
        let domain = *self.signer.domain();
        for entry in &bundle.receipts {
            let computed = crate::receipt::payload_hash_hex(&entry.receipt)?;
            if computed != entry.payload_hash {
                return Err(BrokerError::Invalid(format!(
                    "receipt {} payload hash mismatch",
                    entry.payload_hash
                )));
            }
            let recovered = crate::receipt::recover(&domain, &entry.receipt)?;
            if !accepted
                .iter()
                .any(|signer| signer.eq_ignore_ascii_case(&recovered))
            {
                return Err(BrokerError::Denied(format!(
                    "receipt {} was signed by an unknown signer",
                    entry.payload_hash
                )));
            }
        }

        let agent = bundle.manifest.agent.clone();
        let existing = self.chain.chain(tenant, &agent).await?;
        let from_index = bundle.manifest.from_index as usize;
        let mut matched = 0usize;
        let mut missing = 0usize;
        let mut divergent: Option<serde_json::Value> = None;

        // A paged bundle starts at `from_index`; compare against the same offsets locally.
        // The page must also be anchored: the local receipt before it must match `prev_before`.
        if from_index > 0 {
            let anchor_matches = existing
                .get(from_index - 1)
                .map(|local| Some(local.payload_hash.clone()) == bundle.manifest.prev_before)
                .unwrap_or(false);
            if !anchor_matches {
                return Err(BrokerError::Invalid(format!(
                    "paged bundle starts at index {from_index} but the local chain does not                      contain the matching predecessor (page-by-page import must start at genesis)"
                )));
            }
        }

        for (offset, entry) in bundle.receipts.iter().enumerate() {
            match existing.get(from_index + offset) {
                Some(local) if local.payload_hash == entry.payload_hash => matched += 1,
                Some(local) => {
                    if divergent.is_none() {
                        divergent = Some(serde_json::json!({
                            "index": from_index + offset,
                            "local": local.payload_hash,
                            "incoming": entry.payload_hash,
                        }));
                    }
                }
                None => missing += 1,
            }
        }

        let local_head = self.chain.head_hash(tenant, &agent).await?;
        let report = serde_json::json!({
            "tenant": tenant,
            "agent": agent,
            "bundleReceipts": bundle.receipts.len(),
            "fromIndex": from_index,
            "nextFrom": bundle.manifest.next_from,
            "existing": existing.len(),
            "matched": matched,
            "missing": missing,
            "divergent": divergent,
            "localHead": local_head,
            "bundleHead": bundle.manifest.head,
            "bundleSigner": bundle.manifest.signer,
            "wouldImport": missing,
            "verified": true,
        });
        Ok((bundle.receipts.clone(), report))
    }

    /// Compare a signed bundle against the local chain and report drift (no writes).
    pub async fn import_report(
        &self,
        tenant: &str,
        bundle: &crate::export::ExportBundle,
    ) -> Result<serde_json::Value, BrokerError> {
        let (_, report) = self.inspect_import(tenant, bundle).await?;
        Ok(report)
    }

    /// Import a verified, signed export bundle into this broker's chain store.
    ///
    /// Only bundles whose receipts are individually signed by an accepted broker signer and
    /// whose manifest verifies are accepted; receipts already present are skipped, so
    /// replaying the same archive is idempotent and a partially restored chain is completed.
    pub async fn import_chain(
        &self,
        tenant: &str,
        bundle: &crate::export::ExportBundle,
    ) -> Result<serde_json::Value, BrokerError> {
        let (receipts, report) = self.inspect_import(tenant, bundle).await?;
        if report["divergent"].is_object() {
            return Err(BrokerError::Invalid(format!(
                "chain diverges at index {}: local {} vs imported {}",
                report["divergent"]["index"],
                report["divergent"]["local"],
                report["divergent"]["incoming"],
            )));
        }

        let agent = bundle.manifest.agent.clone();
        let existing = self.chain.chain(tenant, &agent).await?;
        let head_before = self.chain.head_hash(tenant, &agent).await?;
        let from_index = bundle.manifest.from_index as usize;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut index = 0usize;
        // Tracks the chain length as appends land, so a page applies entry by entry.
        let mut local_len = existing.len();

        while index < receipts.len() {
            let entry = &bundle.receipts[index];
            // The chain must reach this entry's index before it can be appended.
            if from_index + index < local_len {
                skipped += 1;
                index += 1;
                continue;
            }
            if from_index + index > local_len {
                return Err(BrokerError::Invalid(format!(
                    "cannot import index {}: the local chain ends at {} (import the earlier page first)",
                    from_index + index,
                    local_len
                )));
            }

            match self.chain.append(tenant, &agent, entry.clone()).await? {
                AppendOutcome::Appended => {
                    imported += 1;
                    local_len += 1;
                    index += 1;
                }
                AppendOutcome::Conflict => {
                    // A concurrent append moved the head: re-read and retry this entry once.
                    let refreshed = self.chain.chain(tenant, &agent).await?;
                    if refreshed
                        .get(index)
                        .map(|local| local.payload_hash == entry.payload_hash)
                        .unwrap_or(false)
                    {
                        skipped += 1;
                        index += 1;
                        continue;
                    }
                    return Err(BrokerError::Invalid(format!(
                        "cannot append receipt {}: chain head does not match its prev",
                        entry.payload_hash
                    )));
                }
            }
        }

        let head = self.chain.head_hash(tenant, &agent).await?;
        crate::metrics::imported_receipts(imported as u64);

        // Signed restore attestation: the broker certifies what it imported and the
        // resulting chain head, so the operation is auditable after the fact.
        let certificate = serde_json::json!({
            "tenant": tenant,
            "agent": agent,
            "imported": imported,
            "skipped": skipped,
            "existingBefore": existing.len(),
            "headBefore": head_before,
            "headAfter": head,
            "bundleHead": bundle.manifest.head,
            "merkleRoot": bundle.manifest.merkle_root,
            "bundleSigner": bundle.manifest.signer,
            "at": chrono::Utc::now().to_rfc3339(),
        });
        let snapshot =
            crate::export::sign_payload(&self.signer, crate::export::RESTORE_DOMAIN, &certificate)
                .await?;
        crate::metrics::restore_attestation();

        // Link the attestation into the tenant's hash-linked ledger, so the restore is part
        // of the same tamper-evident history as the key events (and travels in exports).
        let ledger_details = serde_json::json!({
            "agent": agent,
            "imported": imported,
            "skipped": skipped,
            "headBefore": certificate["headBefore"],
            "headAfter": certificate["headAfter"],
            "bundleHead": bundle.manifest.head,
            "merkleRoot": bundle.manifest.merkle_root,
            "bundleSigner": bundle.manifest.signer,
            "attestationDigest": snapshot.digest,
            "attestationSigner": snapshot.signer,
        });
        if let Err(e) = self
            .append_ledger_event(tenant, "chain.imported", &agent, "", "", ledger_details)
            .await
        {
            tracing::warn!(tenant = %tenant, agent = %agent, "ledger append for import failed: {e}");
        }

        Ok(serde_json::json!({
            "tenant": tenant,
            "agent": agent,
            "existing": existing.len(),
            "imported": imported,
            "skipped": skipped,
            "head": head,
            "attestation": {
                "certificate": certificate,
                "snapshot": snapshot,
            },
        }))
    }

    /// Append a signed, hash-linked event to the tenant's audit ledger. `subject` names the
    /// key, agent, or other object the event is about.
    pub async fn append_ledger_event(
        &self,
        tenant: &str,
        kind: &str,
        subject: &str,
        subject_name: &str,
        prefix: &str,
        details: serde_json::Value,
    ) -> Result<crate::key_events::KeyEvent, BrokerError> {
        let existing = self.key_events.list(tenant).await?;
        let prev_hash = existing.last().map(|event| event.event_hash.clone());
        let mut event = crate::key_events::KeyEvent {
            id: format!("kev_{}", uuid::Uuid::new_v4().simple()),
            tenant: tenant.to_string(),
            kind: kind.to_string(),
            key_id: subject.to_string(),
            key_name: subject_name.to_string(),
            prefix: prefix.to_string(),
            details,
            at: chrono::Utc::now().to_rfc3339(),
            prev_hash,
            event_hash: String::new(),
            signature: None,
        };
        let digest = crate::key_events::event_digest(&event)?;
        event.event_hash = format!("0x{}", hex::encode(digest));
        event.signature = Some(self.signer.sign_hash(&digest).await?);
        self.key_events.append(event.clone()).await?;
        crate::metrics::key_event_recorded();
        Ok(event)
    }

    /// Append a key lifecycle event to the tenant's ledger.
    pub async fn append_key_event(
        &self,
        tenant: &str,
        kind: &str,
        record: &crate::auth::ApiKeyRecord,
        details: serde_json::Value,
    ) -> Result<crate::key_events::KeyEvent, BrokerError> {
        self.append_ledger_event(
            tenant,
            kind,
            &record.id,
            &record.name,
            &record.prefix,
            details,
        )
        .await
    }

    /// One view of a tenant's integrity posture: chains, anchors, ledger, checkpoints.
    pub async fn integrity_report(&self, tenant: &str) -> Result<serde_json::Value, BrokerError> {
        let agents = self.chain.agents_for_tenant(tenant).await?;
        let mut receipts = 0u64;
        let mut unanchored_agents = 0usize;
        for agent in &agents {
            receipts += self.chain.len(tenant, agent).await? as u64;
        }

        let anchors = self.anchors.list(tenant).await?;
        let pending = anchors
            .iter()
            .filter(|record| record.status == "submitted")
            .count();
        for agent in &agents {
            let anchored = anchors.iter().any(|record| {
                record.agent == *agent
                    && matches!(
                        record.status.as_str(),
                        "submitted" | "confirmed" | "finalized"
                    )
            });
            if !anchored {
                unanchored_agents += 1;
            }
        }

        let drift = self.chain_drift(tenant).await?;
        let key_log = self.key_event_log(tenant, None, None).await?;
        let checkpoints = self.chain_checkpoints.list(tenant).await?;

        Ok(serde_json::json!({
            "tenant": tenant,
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "chains": {
                "agents": agents.len(),
                "receipts": receipts,
                "unanchoredAgents": unanchored_agents,
                "driftedAgents": drift.len(),
                "drift": drift,
            },
            "anchors": {
                "count": anchors.len(),
                "pending": pending,
                "latest": anchors.last(),
            },
            "keyEvents": {
                "count": key_log["count"],
                "verified": key_log["verified"],
                "chainValid": key_log["chainValid"],
                "signaturesValid": key_log["signaturesValid"],
            },
            "checkpoints": checkpoints,
        }))
    }

    /// Compare live chains against their checkpoints; returns the drifted agents.
    pub async fn chain_drift(
        &self,
        tenant: &str,
    ) -> Result<Vec<crate::chain_checkpoints::ChainDrift>, BrokerError> {
        let mut drifts = Vec::new();
        for checkpoint in self.chain_checkpoints.list(tenant).await? {
            let entries = self.chain.chain(tenant, &checkpoint.agent).await?;
            let live_len = entries.len() as u64;
            let head_at_checkpoint = entries
                .get(checkpoint.count.saturating_sub(1) as usize)
                .map(|entry| entry.payload_hash.as_str());
            let live_head = entries.last().map(|entry| entry.payload_hash.as_str());
            if let Some(drift) = crate::chain_checkpoints::detect_drift(
                &checkpoint,
                live_len,
                head_at_checkpoint,
                live_head,
            ) {
                drifts.push(drift);
            }
        }
        Ok(drifts)
    }

    /// Compact ledgers older than `retention_days`, leaving a signed checkpoint per tenant.
    pub async fn compact_ledgers(&self, retention_days: u64) -> Result<usize, BrokerError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut removed_total = 0usize;
        for tenant in self.chain.tenants().await? {
            let events = self.key_events.list(&tenant).await?;
            let prunable = events.iter().any(|event| {
                event.kind != "ledger.compacted"
                    && chrono::DateTime::parse_from_rfc3339(&event.at)
                        .map(|at| at.with_timezone(&chrono::Utc) < cutoff)
                        .unwrap_or(false)
            });
            if !prunable {
                continue;
            }
            let checkpoint = crate::key_events::KeyEvent {
                id: format!("kev_{}", uuid::Uuid::new_v4().simple()),
                tenant: tenant.clone(),
                kind: "ledger.compacted".into(),
                key_id: String::new(),
                key_name: String::new(),
                prefix: String::new(),
                details: serde_json::json!({ "retentionDays": retention_days }),
                at: chrono::Utc::now().to_rfc3339(),
                prev_hash: None,
                event_hash: String::new(),
                signature: None,
            };
            let mut checkpoint = checkpoint;
            let digest = crate::key_events::event_digest(&checkpoint)?;
            checkpoint.event_hash = format!("0x{}", hex::encode(digest));
            checkpoint.signature = Some(self.signer.sign_hash(&digest).await?);
            if let Some((removed, _)) = self.key_events.compact(&tenant, cutoff, checkpoint).await?
            {
                removed_total += removed;
                crate::metrics::ledger_compacted(removed as u64);
                tracing::info!(tenant = %tenant, removed, "ledger compacted");
            }
        }
        Ok(removed_total)
    }

    /// A tenant's key-event ledger with a verification verdict (oldest first).
    pub async fn key_event_log(
        &self,
        tenant: &str,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value, BrokerError> {
        let events = self.key_events.list(tenant).await?;
        let chain_ok = crate::key_events::verify_chain(&events);
        let accepted = self.accepted_signers();
        let signatures_ok = events.iter().all(|event| match event.signature.as_deref() {
            Some(signature) => match crate::receipt::recover_hash(
                &crate::key_events::event_digest(event).unwrap_or([0u8; 32]),
                signature,
            ) {
                Ok(recovered) => accepted
                    .iter()
                    .any(|signer| signer.eq_ignore_ascii_case(&recovered)),
                Err(_) => false,
            },
            None => false,
        });
        // Verification verdict covers the whole ledger; `items` is the requested page.
        let total = events.len();
        let page: Vec<&crate::key_events::KeyEvent> = events
            .iter()
            .filter(|event| match since {
                Some(cursor) => chrono::DateTime::parse_from_rfc3339(&event.at)
                    .map(|at| at.with_timezone(&chrono::Utc) > cursor)
                    .unwrap_or(false),
                None => true,
            })
            .collect();
        let limit = limit.unwrap_or(500).clamp(1, 5_000);
        let has_more = page.len() > limit;
        let page: Vec<&crate::key_events::KeyEvent> = page.into_iter().take(limit).collect();
        let next_since = page.last().map(|event| event.at.clone());

        Ok(serde_json::json!({
            "tenant": tenant,
            "count": total,
            "returned": page.len(),
            "hasMore": has_more,
            "nextSince": next_since,
            "verified": chain_ok && signatures_ok,
            "chainValid": chain_ok,
            "signaturesValid": signatures_ok,
            "items": page,
        }))
    }

    /// Acknowledge an alert condition: repeats stay quiet until severity exceeds `value`.
    pub async fn ack_alert(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
        value: u64,
    ) -> Result<crate::alert_acks::AlertAck, BrokerError> {
        let ack = crate::alert_acks::AlertAck {
            event: event.to_string(),
            dedup_key: dedup_key.to_string(),
            value,
            acked_at: chrono::Utc::now().to_rfc3339(),
        };
        self.alert_acks.set(tenant, ack.clone()).await?;
        Ok(ack)
    }

    /// Current severity for a condition, so an ack can default to "what I am seeing now".
    pub async fn current_condition_value(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
    ) -> Result<Option<u64>, BrokerError> {
        match event {
            "anchor.gap" => Ok(self
                .anchor_gaps(tenant)
                .await?
                .iter()
                .find(|gap| gap["agent"].as_str() == Some(dedup_key))
                .and_then(|gap| gap["gap"].as_u64())),
            _ => Ok(None),
        }
    }

    /// Decide whether a key must be narrowed by the tenant's auto-remediation policy.
    /// Returns the template to apply and the reasons, or `None` when no action is needed.
    pub async fn remediation_decision(
        &self,
        tenant: &str,
        record: &crate::auth::ApiKeyRecord,
    ) -> Result<Option<(crate::auth::KeyTemplate, Vec<String>)>, BrokerError> {
        let Some(policy) = self.remediation_policies.get(tenant).await? else {
            return Ok(None);
        };
        if !policy.enabled {
            return Ok(None);
        }
        let Some(template) = crate::auth::key_template(&policy.template) else {
            tracing::warn!(
                tenant = %tenant,
                template = %policy.template,
                "auto-remediation template missing"
            );
            return Ok(None);
        };
        // A preset that changed since the policy was approved must not silently change what
        // gets enforced: the policy goes stale until an operator re-approves it.
        if let Some(pinned) = policy.template_version {
            if pinned != template.version {
                crate::metrics::remediation_stale();
                tracing::warn!(
                    tenant = %tenant,
                    template = template.name,
                    pinned,
                    current = template.version,
                    "auto-remediation policy is stale (template was revised); skipping"
                );
                return Ok(None);
            }
        }
        let reasons = crate::auth::scope_exceeds(&record.scope, &template.scope);
        if reasons.is_empty() {
            return Ok(None);
        }
        Ok(Some((template, reasons)))
    }

    /// Probe a tenant's anchor configuration: RPC reachability, chain id, and whether the
    /// contract is actually deployed there. Read-only; never submits anything.
    pub async fn check_anchor_target(
        &self,
        tenant: &str,
    ) -> Result<serde_json::Value, BrokerError> {
        let target = self.anchor_targets.get(tenant).await?;
        let declared_chain = target.as_ref().map(|target| target.chain_id).unwrap_or(0);
        let submitter = self.submitter_for(target)?;
        self.egress.check_resolved(submitter.rpc_url()).await?;

        let mut report = serde_json::json!({
            "rpcUrl": submitter.rpc_url(),
            "contract": submitter.contract_hex(),
        });
        let rpc = crate::eth::RpcClient::new(submitter.rpc_url());
        match rpc.chain_id().await {
            Ok(chain_id) => {
                report["rpcReachable"] = serde_json::json!(true);
                report["chainId"] = serde_json::json!(chain_id);
                report["chainIdMatches"] =
                    serde_json::json!(declared_chain == 0 || declared_chain == chain_id);
            }
            Err(e) => {
                report["rpcReachable"] = serde_json::json!(false);
                report["error"] = serde_json::json!(e.to_string());
                return Ok(report);
            }
        }
        match rpc.block_number().await {
            Ok(block) => report["blockNumber"] = serde_json::json!(block),
            Err(e) => report["error"] = serde_json::json!(e.to_string()),
        }
        match rpc.code_at(&submitter.contract_hex()).await {
            Ok(code) => {
                let deployed = code.trim_start_matches("0x") != "0x" && code.len() > 2;
                report["contractDeployed"] = serde_json::json!(deployed);
                if !deployed {
                    report["error"] =
                        serde_json::json!("no contract code at the configured address");
                }
            }
            Err(e) => report["error"] = serde_json::json!(e.to_string()),
        }
        Ok(report)
    }

    /// Configure (or clear) a tenant's alert webhook. The URL is SSRF-checked like a tenant
    /// anchor RPC URL, and the token is encrypted at rest.
    pub async fn set_alert_target(
        &self,
        tenant: &str,
        mut target: crate::alerts::AlertTarget,
    ) -> Result<crate::alerts::AlertTarget, BrokerError> {
        self.rpc_policy.validate(&target.url)?;
        target.token = match target.token.take() {
            None => None,
            Some(token) if token.trim().is_empty() => None,
            Some(token) => {
                let envelope = self.secrets.as_ref().ok_or_else(|| {
                    BrokerError::NotConfigured(
                        "TENANT_SECRET_ENC_KEY must be set to store an alert token".into(),
                    )
                })?;
                Some(envelope.encrypt(&token)?)
            }
        };
        self.alert_router.set_target(tenant, target.clone()).await?;
        Ok(target)
    }

    /// Read a tenant's alert target for display (token decrypted).
    pub async fn alert_target(
        &self,
        tenant: &str,
    ) -> Result<Option<crate::alerts::AlertTarget>, BrokerError> {
        let Some(stored) = self.alert_router.target(tenant).await? else {
            return Ok(None);
        };
        let token = match stored.token.as_deref() {
            Some(encrypted) => Some(self.private_key_plaintext(encrypted)?),
            None => None,
        };
        Ok(Some(crate::alerts::AlertTarget {
            url: stored.url,
            token,
            events: stored.events,
            auto_ack_below: stored.auto_ack_below,
        }))
    }

    /// Notify the configured webhook that a chain crossed the anchor gap threshold.
    /// Repeat-suppressed per (tenant, agent); best-effort, never fails the sweep.
    pub async fn alert_anchor_gap(
        &self,
        tenant: &str,
        agent: &str,
        gap: u64,
        chain_length: u64,
    ) -> Result<bool, BrokerError> {
        self.send_alert(
            tenant,
            "anchor.gap",
            agent,
            gap,
            serde_json::json!({
                "tenant": tenant,
                "agent": agent,
                "gap": gap,
                "chainLength": chain_length,
                "threshold": self.anchor_gap_threshold,
                "detectedAt": chrono::Utc::now().to_rfc3339(),
            }),
        )
        .await
    }

    /// Deliver a discrete event (key lifecycle changes): every occurrence is sent, with no
    /// repeat suppression or acknowledgement. Best-effort and counted.
    pub async fn send_event(
        &self,
        tenant: &str,
        event: &str,
        payload: serde_json::Value,
    ) -> Result<crate::alerts::Delivery, BrokerError> {
        let Some((url, token)) = self.alert_router.destination(tenant, event).await? else {
            return Ok(crate::alerts::Delivery::not_attempted());
        };
        let mut body = payload;
        if let Some(object) = body.as_object_mut() {
            object.insert("event".into(), serde_json::Value::String(event.to_string()));
        }
        let snapshot =
            crate::export::sign_payload(&self.signer, crate::export::ALERT_DOMAIN, &body).await?;
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(snapshot)
                    .map_err(|e| BrokerError::Internal(format!("serialize event: {e}")))?,
            );
        }
        let mut request = self.http.post(&url).json(&body);
        if let Some(token) = &token {
            request = request.header("x-tessera-alert-token", token);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                crate::metrics::alert_sent();
                Ok(crate::alerts::Delivery::delivered(
                    response.status().as_u16(),
                ))
            }
            Ok(response) => {
                crate::metrics::alert_failure();
                tracing::warn!(status = %response.status(), event, "event webhook rejected");
                Ok(crate::alerts::Delivery {
                    attempted: true,
                    delivered: false,
                    status: Some(response.status().as_u16()),
                })
            }
            Err(e) => {
                crate::metrics::alert_failure();
                tracing::warn!(event, "event webhook failed: {e}");
                Ok(crate::alerts::Delivery {
                    attempted: true,
                    delivered: false,
                    status: None,
                })
            }
        }
    }

    /// Send a signed alert event to the tenant's (or global) webhook. Repeat-suppressed per
    /// dedup key; failures are retried after `alert_retry_secs`, never propagated.
    pub async fn send_alert(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
        condition_value: u64,
        payload: serde_json::Value,
    ) -> Result<bool, BrokerError> {
        // Auto-ack policy: low-severity alerts are counted, never delivered.
        if let Some(threshold) = self.alert_router.auto_ack_below(tenant).await? {
            if condition_value <= threshold {
                crate::metrics::alert_auto_acked();
                tracing::info!(
                    tenant = %tenant,
                    event,
                    condition_value,
                    threshold,
                    "alert auto-acknowledged by policy"
                );
                return Ok(false);
            }
        }

        // An acknowledged condition stays quiet until it gets worse; an escalation past an
        // ack bypasses the repeat window (it is new information, not a reminder).
        let ack = self.alert_acks.get(tenant, event, dedup_key).await?;
        if !crate::alert_acks::should_fire(ack.as_ref(), condition_value) {
            return Ok(false);
        }
        let escalated = ack.is_some();
        let Some((url, token)) = self.alert_router.destination(tenant, event).await? else {
            return Ok(false);
        };
        let key = format!("{tenant}\u{0}{event}\u{0}{dedup_key}");
        {
            let mut alerts = self.gap_alerts.lock().await;
            let now = std::time::Instant::now();
            if !escalated {
                if let Some(next_allowed) = alerts.get(&key) {
                    if *next_allowed > now {
                        return Ok(false);
                    }
                }
            }
            alerts.insert(
                key.clone(),
                now + std::time::Duration::from_secs(self.alert_retry_secs),
            );
        }

        // The signature covers the event and severity, so receivers can trust them.
        let mut body = payload;
        if let Some(object) = body.as_object_mut() {
            object.insert("event".into(), serde_json::Value::String(event.to_string()));
            object.insert("conditionValue".into(), serde_json::json!(condition_value));
        }
        let snapshot =
            crate::export::sign_payload(&self.signer, crate::export::ALERT_DOMAIN, &body).await?;
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(snapshot)
                    .map_err(|e| BrokerError::Internal(format!("serialize alert: {e}")))?,
            );
        }

        let mut request = self.http.post(&url).json(&body);
        if let Some(token) = &token {
            request = request.header("x-tessera-alert-token", token);
        }
        let delivered = match request.send().await {
            Ok(response) if response.status().is_success() => {
                crate::metrics::alert_sent();
                true
            }
            Ok(response) => {
                crate::metrics::alert_failure();
                tracing::warn!(status = %response.status(), event, "alert webhook rejected");
                false
            }
            Err(e) => {
                crate::metrics::alert_failure();
                tracing::warn!(event, "alert webhook failed: {e}");
                false
            }
        };

        let mut alerts = self.gap_alerts.lock().await;
        let window = if delivered {
            self.alert_repeat_secs.max(60)
        } else {
            self.alert_retry_secs
        };
        alerts.insert(
            key,
            std::time::Instant::now() + std::time::Duration::from_secs(window),
        );
        Ok(delivered)
    }

    /// Load the most recent integrity snapshot for a tenant from `dir` (payload only).
    pub fn previous_snapshot(dir: &std::path::Path, tenant: &str) -> Option<serde_json::Value> {
        let prefix = format!("integrity-{tenant}-");
        let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .ok()?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with(&prefix) && name.ends_with(".json"))
                    .unwrap_or(false)
            })
            .collect();
        // Filenames embed a fixed-width timestamp, so lexicographic order is chronological.
        candidates.sort();
        let path = candidates.last()?;
        let raw = std::fs::read_to_string(path).ok()?;
        let mut value: serde_json::Value = serde_json::from_str(&raw).ok()?;
        if let Some(object) = value.as_object_mut() {
            object.remove("snapshot");
            object.remove("changes");
        }
        Some(value)
    }

    /// Compare two posture payloads and report the changed fields. `unexpected` marks
    /// changes that should never happen silently (loss of evidence, broken ledger, drift).
    pub fn diff_snapshots(
        previous: &serde_json::Value,
        current: &serde_json::Value,
    ) -> Vec<serde_json::Value> {
        let fields: [(&str, Vec<&str>); 9] = [
            ("chains.agents", vec!["chains", "agents"]),
            ("chains.receipts", vec!["chains", "receipts"]),
            (
                "chains.unanchoredAgents",
                vec!["chains", "unanchoredAgents"],
            ),
            ("chains.driftedAgents", vec!["chains", "driftedAgents"]),
            ("anchors.count", vec!["anchors", "count"]),
            ("keyEvents.count", vec!["keyEvents", "count"]),
            ("keyEvents.verified", vec!["keyEvents", "verified"]),
            ("checkpoints", vec!["checkpoints"]),
            ("settings.digest", vec!["settings", "digest"]),
        ];
        let read = |value: &serde_json::Value, path: &[&str]| -> serde_json::Value {
            let mut cursor = value;
            for segment in path {
                cursor = match cursor.get(*segment) {
                    Some(next) => next,
                    None => return serde_json::Value::Null,
                };
            }
            if path == ["checkpoints"] {
                return serde_json::json!(cursor.as_array().map(Vec::len).unwrap_or(0));
            }
            cursor.clone()
        };

        let mut changes = Vec::new();
        for (name, path) in fields {
            let from = read(previous, &path);
            let to = read(current, &path);
            if from == to {
                continue;
            }
            let unexpected = match name {
                // Evidence loss or integrity regressions are unexpected; growth is not.
                "chains.receipts" | "chains.agents" | "checkpoints" => {
                    to.as_u64().unwrap_or(0) < from.as_u64().unwrap_or(0)
                }
                "keyEvents.verified" => from.as_bool() == Some(true) && to.as_bool() != Some(true),
                "chains.driftedAgents" | "chains.unanchoredAgents" => {
                    to.as_u64().unwrap_or(0) > from.as_u64().unwrap_or(0)
                }
                _ => false,
            };
            changes.push(serde_json::json!({
                "field": name,
                "from": from,
                "to": to,
                "unexpected": unexpected,
            }));
        }
        changes
    }

    /// Write a signed, indexed snapshot of an arbitrary posture payload to `dir`.
    /// Used for scheduled integrity snapshots alongside the archives.
    pub async fn write_signed_snapshot(
        &self,
        dir: &std::path::Path,
        kind: &str,
        tenant: &str,
        payload: serde_json::Value,
    ) -> Result<(std::path::PathBuf, crate::export::SignedPayload), BrokerError> {
        let snapshot =
            crate::export::sign_payload(&self.signer, crate::export::INTEGRITY_DOMAIN, &payload)
                .await?;
        let mut document = payload;
        if let Some(object) = document.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(&snapshot)
                    .map_err(|e| BrokerError::Internal(format!("serialize snapshot: {e}")))?,
            );
        }
        let bytes = serde_json::to_vec_pretty(&document)
            .map_err(|e| BrokerError::Internal(format!("serialize snapshot document: {e}")))?;

        std::fs::create_dir_all(dir)
            .map_err(|e| BrokerError::Internal(format!("archive dir {}: {e}", dir.display())))?;
        let safe_tenant: String = tenant
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let filename = format!(
            "{kind}-{}-{}-{}.json",
            safe_tenant,
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let path = dir.join(filename);
        std::fs::write(&path, &bytes).map_err(|e| {
            BrokerError::Internal(format!("snapshot write {}: {e}", path.display()))
        })?;

        // Index it like an archive so rewrites are detectable.
        let entry = serde_json::json!({
            "kind": kind,
            "tenant": tenant,
            "file": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
            "digest": format!("0x{}", hex::encode(crate::merkle::keccak(&bytes))),
            "bytes": bytes.len(),
            "writtenAt": chrono::Utc::now().to_rfc3339(),
        });
        let entry_snapshot =
            crate::export::sign_payload(&self.signer, crate::export::ARCHIVE_INDEX_DOMAIN, &entry)
                .await?;
        let mut line = entry;
        if let Some(object) = line.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(entry_snapshot)
                    .map_err(|e| BrokerError::Internal(format!("serialize index entry: {e}")))?,
            );
        }
        let mut jsonl = serde_json::to_string(&line)
            .map_err(|e| BrokerError::Internal(format!("serialize index line: {e}")))?;
        jsonl.push('\n');
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(crate::export::ARCHIVE_INDEX_FILE))
            .map_err(|e| BrokerError::Internal(format!("index open: {e}")))?;
        file.write_all(jsonl.as_bytes())
            .map_err(|e| BrokerError::Internal(format!("index append: {e}")))?;

        crate::metrics::integrity_snapshot();
        Ok((path, snapshot))
    }

    /// Prune archive/snapshot files older than `retention_days`, always keeping the newest
    /// snapshot per tenant and the append-only index. Every deletion is recorded as a signed
    /// `retention.pruned` index entry so the index still explains what happened to the file.
    pub async fn prune_evidence(
        &self,
        dir: &std::path::Path,
        retention_days: u64,
    ) -> Result<usize, BrokerError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);

        let mut archives: Vec<(String, std::path::PathBuf)> = Vec::new();
        let mut snapshots: std::collections::HashMap<String, Vec<(String, std::path::PathBuf)>> =
            std::collections::HashMap::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            // `tessera-export-<tenant>-<timestamp>-<rand>.tar.gz` /
            // `integrity-<tenant>-<timestamp>-<rand>.json`. Tenant ids may contain hyphens, so
            // parse from the right: <rand> then <timestamp> then the tenant as the remainder.
            let stem = if name.starts_with("tessera-export-") && name.ends_with(".tar.gz") {
                Some(&name["tessera-export-".len()..name.len() - ".tar.gz".len()])
            } else if name.starts_with("integrity-") && name.ends_with(".json") {
                Some(&name["integrity-".len()..name.len() - ".json".len()])
            } else {
                None
            };
            let Some(stem) = stem else {
                continue;
            };
            let mut parts = stem.rsplitn(3, '-');
            let _random = parts.next();
            let timestamp = parts.next();
            let tenant_part = parts.next();
            let (Some(tenant_part), Some(timestamp)) = (tenant_part, timestamp) else {
                // Malformed names are skipped rather than mis-parsed.
                continue;
            };
            if name.starts_with("tessera-export-") {
                archives.push((timestamp.to_string(), path));
            } else {
                snapshots
                    .entry(tenant_part.to_string())
                    .or_default()
                    .push((timestamp.to_string(), path));
            }
        }

        // Newest snapshot per tenant is retained regardless of age.
        let mut keep: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        for per_tenant in snapshots.values_mut() {
            per_tenant.sort();
            if let Some((_, newest)) = per_tenant.last() {
                keep.insert(newest.clone());
            }
        }

        let mut pruned_files: Vec<String> = Vec::new();
        let mut pruned_filenames: Vec<String> = Vec::new();
        for (timestamp, path) in archives.iter().chain(snapshots.values().flatten()) {
            if keep.contains(path) {
                continue;
            }
            // Filenames end with a literal `Z`; strip it and parse as naive UTC.
            let Ok(stamp) = chrono::NaiveDateTime::parse_from_str(
                timestamp.trim_end_matches('Z'),
                "%Y%m%dT%H%M%S",
            ) else {
                continue;
            };
            if stamp.and_utc() >= cutoff {
                continue;
            }
            if std::fs::remove_file(path).is_ok() {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    pruned_files.push(name.to_string());
                    pruned_filenames.push(name.to_string());
                }
                crate::metrics::evidence_pruned();
            }
        }
        if pruned_files.is_empty() {
            return Ok(0);
        }

        let entry = serde_json::json!({
            "kind": "retention.pruned",
            "prunedAt": chrono::Utc::now().to_rfc3339(),
            "retentionDays": retention_days,
            "files": pruned_files,
        });
        let snapshot =
            crate::export::sign_payload(&self.signer, crate::export::ARCHIVE_INDEX_DOMAIN, &entry)
                .await?;
        let mut line = entry;
        if let Some(object) = line.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(snapshot)
                    .map_err(|e| BrokerError::Internal(format!("serialize index entry: {e}")))?,
            );
        }
        let mut jsonl = serde_json::to_string(&line)
            .map_err(|e| BrokerError::Internal(format!("serialize index line: {e}")))?;
        jsonl.push('\n');
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(crate::export::ARCHIVE_INDEX_FILE))
            .and_then(|mut file| file.write_all(jsonl.as_bytes()))
            .map_err(|e| BrokerError::Internal(format!("index append: {e}")))?;

        tracing::info!(
            pruned = pruned_filenames.len(),
            dir = %dir.display(),
            "evidence pruned"
        );
        Ok(pruned_filenames.len())
    }

    /// Write a signed tenant archive to `dir` (evidence retention outside the database).
    /// Returns the path written, or `None` when the tenant has no agents.
    pub async fn write_tenant_archive(
        &self,
        tenant: &str,
        dir: &std::path::Path,
    ) -> Result<Option<std::path::PathBuf>, BrokerError> {
        let bundle = self.export_tenant(tenant).await?;
        if bundle.agents.is_empty() {
            return Ok(None);
        }
        let bytes = crate::export::build_tenant_archive(
            &bundle,
            "tessera-verify manifest.json --expect-signer <address from README>",
        )?;
        std::fs::create_dir_all(dir)
            .map_err(|e| BrokerError::Internal(format!("archive dir {}: {e}", dir.display())))?;
        let safe_tenant: String = tenant
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        // Timestamp + random suffix: two archives written in the same second must not
        // overwrite each other (the index records every write).
        let filename = format!(
            "tessera-export-{}-{}-{}.tar.gz",
            safe_tenant,
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let path = dir.join(filename);
        std::fs::write(&path, &bytes)
            .map_err(|e| BrokerError::Internal(format!("archive write {}: {e}", path.display())))?;

        // Append a signed entry to the archive index: an append-only record of what was
        // archived when, so deletions/rewrites after the fact are detectable.
        let entry = serde_json::json!({
            "kind": "archive",
            "tenant": tenant,
            "file": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
            "digest": format!("0x{}", hex::encode(crate::merkle::keccak(&bytes))),
            "bytes": bytes.len(),
            "writtenAt": chrono::Utc::now().to_rfc3339(),
            "merkleRoot": bundle.manifest.merkle_root,
            "agents": bundle.manifest.agent_count,
            "receipts": bundle.manifest.receipt_count,
        });
        let snapshot =
            crate::export::sign_payload(&self.signer, crate::export::ARCHIVE_INDEX_DOMAIN, &entry)
                .await?;
        let mut line = entry;
        if let Some(object) = line.as_object_mut() {
            object.insert(
                "snapshot".into(),
                serde_json::to_value(snapshot)
                    .map_err(|e| BrokerError::Internal(format!("serialize index entry: {e}")))?,
            );
        }
        let mut jsonl = serde_json::to_string(&line)
            .map_err(|e| BrokerError::Internal(format!("serialize index line: {e}")))?;
        jsonl.push('\n');
        let index_path = dir.join(crate::export::ARCHIVE_INDEX_FILE);
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)
            .map_err(|e| {
                BrokerError::Internal(format!("index open {}: {e}", index_path.display()))
            })?;
        file.write_all(jsonl.as_bytes()).map_err(|e| {
            BrokerError::Internal(format!("index append {}: {e}", index_path.display()))
        })?;

        // Checkpoint every archived chain so later drift is detectable.
        for agent in &bundle.agents {
            let checkpoint = crate::chain_checkpoints::ChainCheckpoint {
                agent: agent.manifest.agent.clone(),
                head: agent.manifest.head.clone(),
                count: agent.manifest.receipt_count,
                taken_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = self.chain_checkpoints.set(tenant, checkpoint).await {
                tracing::warn!(tenant = %tenant, "checkpoint write failed: {e}");
            }
        }

        // Replicate to the configured second location and verify the copy by digest.
        if let Some(replica_dir) = self.archive_replica_dir.as_deref() {
            let replica_dir = std::path::Path::new(replica_dir);
            let replica = replica_dir.join(path.file_name().unwrap_or_default());
            let copied = std::fs::create_dir_all(replica_dir)
                .and_then(|_| std::fs::write(&replica, &bytes))
                .and_then(|_| std::fs::read(&replica))
                .map_err(|e| {
                    BrokerError::Internal(format!("replica write {}: {e}", replica.display()))
                });
            match copied {
                Ok(readback)
                    if crate::merkle::keccak(&readback) == crate::merkle::keccak(&bytes) =>
                {
                    crate::metrics::archive_replicated();
                    tracing::info!(replica = %replica.display(), "archive replicated");
                }
                Ok(_) => {
                    crate::metrics::archive_replica_failure();
                    tracing::warn!(replica = %replica.display(), "replica digest mismatch");
                }
                Err(e) => {
                    crate::metrics::archive_replica_failure();
                    tracing::warn!("{e}");
                }
            }
        }

        crate::metrics::archive_written();
        Ok(Some(path))
    }

    /// Tenant signer addresses a verifier should accept for this tenant: the current key
    /// (if any) plus every previously rotated key.
    pub async fn accepted_tenant_signers(&self, tenant: &str) -> Result<Vec<String>, BrokerError> {
        let Some(target) = self.anchor_targets.get(tenant).await? else {
            return Ok(Vec::new());
        };
        let mut signers = target.signer_history.clone();
        if let Some(stored) = target.private_key.as_deref() {
            let plaintext = self.private_key_plaintext(stored)?;
            let signer = crate::signer::LocalSigner::from_hex(&plaintext)?;
            let address = crate::signer::DigestSigner::address_hex(&signer);
            if !signers.iter().any(|s| s.eq_ignore_ascii_case(&address)) {
                signers.insert(0, address);
            }
        }
        Ok(signers)
    }

    /// Effective limits for a tenant: broker configuration merged with policy limits.
    /// Read-only introspection for operators and tenants (no secrets).
    pub async fn effective_limits(&self, tenant: &str) -> Result<serde_json::Value, BrokerError> {
        use std::collections::BTreeMap;

        let policies = self.policies.policies_for(tenant).await?;

        // Effective per-resource budgets: config, tightened by any policy limit.
        let mut tool_limits: BTreeMap<String, u32> =
            self.tool_rate_limits.iter().cloned().collect();
        for policy in &policies {
            for (resource, per_minute) in &policy.limits.tool_rate_limits {
                tool_limits
                    .entry(resource.clone())
                    .and_modify(|existing| *existing = (*existing).min(*per_minute))
                    .or_insert(*per_minute);
            }
        }

        let policy_limits: Vec<serde_json::Value> = policies
            .iter()
            .filter(|policy| {
                policy.limits.max_ttl_seconds.is_some()
                    || policy.limits.agent_rate_limit_per_min.is_some()
                    || !policy.limits.tool_rate_limits.is_empty()
            })
            .map(|policy| {
                serde_json::json!({
                    "id": policy.id,
                    "version": policy.version,
                    "limits": policy.limits,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "tenant": tenant,
            "agentRateLimitPerMin": self.agent_rate_limit_per_min,
            "toolRateLimits": tool_limits,
            "defaultCredentialTtlSeconds": self.default_ttl_seconds,
            "maxCredentialTtlSeconds": self.max_ttl_seconds,
            "retentionDays": self.retention_days,
            "anchorConfirmations": self.anchor_confirmations,
            "strictEgress": self.egress.is_enabled(),
            "distributedRateLimiter": self.rate_limiter.distributed(),
            "quota": {
                "enabled": self.quota.is_enabled(),
                "providers": self.quota.snapshot(),
            },
            "policiesWithLimits": policy_limits,
        }))
    }

    /// Prove that a receipt is covered by an anchored Merkle root, optionally
    /// cross-checked against the chain's own event log.
    pub async fn receipt_proof(
        &self,
        tenant: &str,
        agent: &str,
        receipt: Option<&str>,
        index: Option<usize>,
    ) -> Result<serde_json::Value, BrokerError> {
        let entries = self.chain.chain(tenant, agent).await?;
        if entries.len() > crate::export::MAX_EXPORT_RECEIPTS {
            return Err(BrokerError::Invalid(format!(
                "chain has {} receipts; inline proofs are capped at {} (use the export)",
                entries.len(),
                crate::export::MAX_EXPORT_RECEIPTS
            )));
        }
        let position = match (receipt, index) {
            (Some(hash), None) => entries
                .iter()
                .position(|entry| entry.payload_hash.eq_ignore_ascii_case(hash))
                .ok_or_else(|| BrokerError::NotFound(format!("receipt {hash}")))?,
            (None, Some(index)) => {
                if index >= entries.len() {
                    return Err(BrokerError::NotFound(format!("receipt index {index}")));
                }
                index
            }
            _ => {
                return Err(BrokerError::Invalid(
                    "provide exactly one of receipt or index".into(),
                ))
            }
        };

        // Tightest live anchor that covers this position.
        let mut records: Vec<_> = self
            .anchors
            .list(tenant)
            .await?
            .into_iter()
            .filter(|record| {
                record.agent == agent
                    && record.count as usize > position
                    && matches!(
                        record.status.as_str(),
                        "submitted" | "confirmed" | "finalized"
                    )
            })
            .collect();
        records.sort_by_key(|record| record.count);

        let mut matched = None;
        for record in records {
            let count = record.count as usize;
            if count > entries.len() {
                // The chain was pruned below the anchor window; cannot rebuild the leaves.
                continue;
            }
            let mut leaves = Vec::with_capacity(count);
            for entry in &entries[..count] {
                leaves.push(crate::merkle::leaf_for_receipt(&entry.receipt)?);
            }
            let tree = crate::merkle::MerkleTree::new(leaves);
            let root = format!("0x{}", hex::encode(tree.root()));
            if root == record.merkle_root {
                matched = Some((record, tree));
                break;
            }
        }
        let Some((record, tree)) = matched else {
            return Err(BrokerError::NotFound(
                "no live anchor covers this receipt".into(),
            ));
        };

        let leaf = entries[position].payload_hash.clone();
        let proof: Vec<String> = tree
            .proof(position)
            .into_iter()
            .map(|sibling| format!("0x{}", hex::encode(sibling)))
            .collect();

        // Cross-check on-chain when a submitter is available and the anchor was submitted.
        let onchain = match self.anchor_targets.get(tenant).await? {
            Some(target) if record.tx_hash.is_some() => {
                let submitter = self.submitter_for(Some(target))?;
                self.egress.check_resolved(submitter.rpc_url()).await?;
                let tenant_hash = merkle::keccak(tenant.as_bytes());
                match parse_hex32(&record.merkle_root) {
                    Ok(root) => match submitter.verify_anchored(tenant_hash, root, 100_000).await {
                        Ok(Some(claim)) => serde_json::json!({
                            "checked": true,
                            "anchored": true,
                            "blockNumber": claim.block_number,
                            "confirmations": claim.confirmations,
                            "batchIndex": claim.batch_index,
                        }),
                        Ok(None) => serde_json::json!({ "checked": true, "anchored": false }),
                        Err(e) => serde_json::json!({ "checked": false, "error": e.to_string() }),
                    },
                    Err(e) => serde_json::json!({ "checked": false, "error": e.to_string() }),
                }
            }
            _ => serde_json::json!({ "checked": false }),
        };

        Ok(serde_json::json!({
            "tenant": tenant,
            "agent": agent,
            "receipt": leaf,
            "index": position,
            "count": record.count,
            "chainLength": entries.len(),
            "root": record.merkle_root,
            "proof": proof,
            "anchor": {
                "id": record.id,
                "status": record.status,
                "txHash": record.tx_hash,
                "blockNumber": record.block_number,
            },
            "onchain": onchain,
        }))
    }

    /// A tenant's own co-signing key, when one is configured (decrypted).
    async fn tenant_cosigner(
        &self,
        tenant: &str,
    ) -> Result<Option<std::sync::Arc<dyn crate::signer::DigestSigner>>, BrokerError> {
        let Some(target) = self.anchor_targets.get(tenant).await? else {
            return Ok(None);
        };
        let Some(stored) = target.private_key.as_deref() else {
            return Ok(None);
        };
        let secrets = self.secrets.as_ref().ok_or_else(|| {
            BrokerError::NotConfigured(
                "tenant signing key is configured but TENANT_SECRET_ENC_KEY is unset".into(),
            )
        })?;
        let plaintext = secrets.decrypt(stored)?;
        Ok(Some(std::sync::Arc::new(
            crate::signer::LocalSigner::from_hex(&plaintext)?,
        )))
    }

    fn signature_hex(r: [u8; 32], s: [u8; 32], recid: u8) -> String {
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&r);
        out.extend_from_slice(&s);
        out.push(recid + 27);
        format!("0x{}", hex::encode(out))
    }

    /// Build the signed export bundle for one agent (or one deterministic page of it).
    async fn build_agent_export(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<crate::export::ExportBundle, BrokerError> {
        self.build_agent_export_page(tenant, agent, None, None)
            .await
    }

    /// Export a slice of an agent's chain, ordered by chain index. `from` defaults to the
    /// most recent `MAX_EXPORT_RECEIPTS` window; `limit` bounds the page and the response
    /// reports `nextFrom` when more receipts follow, so long chains are fully recoverable
    /// page by page (each page verifies on its own against its recorded predecessor hash).
    pub async fn build_agent_export_page(
        &self,
        tenant: &str,
        agent: &str,
        from: Option<u64>,
        limit: Option<u64>,
    ) -> Result<crate::export::ExportBundle, BrokerError> {
        let entries = self.chain.chain(tenant, agent).await?;
        let chain_length = entries.len() as u64;
        let limit = limit
            .unwrap_or(crate::export::MAX_EXPORT_RECEIPTS as u64)
            .clamp(1, crate::export::MAX_EXPORT_RECEIPTS as u64);
        let from = match from {
            Some(from) => from.min(chain_length),
            None => chain_length.saturating_sub(limit),
        };
        let end = (from + limit).min(chain_length);
        let receipts: Vec<crate::chain::ChainEntry> = entries[from as usize..end as usize].to_vec();
        let truncated = from > 0;
        let next_from = if end < chain_length { Some(end) } else { None };
        let prev_before = if from == 0 {
            None
        } else {
            entries
                .get(from as usize - 1)
                .map(|entry| entry.payload_hash.clone())
        };

        let mut leaves = Vec::with_capacity(receipts.len());
        for entry in &receipts {
            leaves.push(crate::merkle::leaf_for_receipt(&entry.receipt)?);
        }
        let root = crate::merkle::MerkleTree::new(leaves).root();

        let mut manifest = crate::export::ExportManifest {
            version: crate::export::EXPORT_VERSION,
            tenant: tenant.to_string(),
            agent: agent.to_string(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            receipt_count: receipts.len() as u64,
            chain_length,
            head: receipts.last().map(|entry| entry.payload_hash.clone()),
            merkle_root: format!("0x{}", hex::encode(root)),
            signer: self.signer.address_hex(),
            signature: String::new(),
            tenant_signer: None,
            tenant_signature: None,
            truncated,
            from_index: from,
            prev_before,
            next_from,
        };

        // The tenant address is part of the signed payload: set it before signing. A
        // configured-but-unusable key fails the export loudly instead of producing a
        // bundle that looks tenant-signed.
        let cosigner = self.tenant_cosigner(tenant).await?;
        if let Some(cosigner) = &cosigner {
            manifest.tenant_signer = Some(cosigner.address_hex());
        }
        let digest = crate::export::manifest_digest(&manifest)?;
        manifest.signature = self.signer.sign_hash(&digest).await?;
        if let Some(cosigner) = &cosigner {
            let (r, s, recid) =
                crate::signer::DigestSigner::sign_prehash(cosigner.as_ref(), &digest).await?;
            manifest.tenant_signature = Some(Self::signature_hex(r, s, recid));
        }
        Ok(crate::export::ExportBundle { manifest, receipts })
    }

    /// Export an agent's chain as a signed, self-contained audit bundle.
    pub async fn export_chain(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<crate::export::ExportBundle, BrokerError> {
        let bundle = self.build_agent_export(tenant, agent).await?;
        crate::metrics::export_bundle();
        Ok(bundle)
    }

    /// Export every agent of a tenant as one signed archive (capped at
    /// `MAX_EXPORT_AGENTS`, each agent capped at `MAX_EXPORT_RECEIPTS`).
    pub async fn export_tenant(
        &self,
        tenant: &str,
    ) -> Result<crate::export::TenantExportBundle, BrokerError> {
        let mut agents = self.chain.agents_for_tenant(tenant).await?;
        agents.sort();
        let truncated = agents.len() > crate::export::MAX_EXPORT_AGENTS;
        if truncated {
            agents.truncate(crate::export::MAX_EXPORT_AGENTS);
        }

        let mut bundles = Vec::with_capacity(agents.len());
        for agent in &agents {
            bundles.push(self.build_agent_export(tenant, agent).await?);
        }

        let mut leaves = Vec::new();
        let mut heads = Vec::new();
        let mut total = 0u64;
        let mut any_truncated = truncated;
        for bundle in &bundles {
            total += bundle.manifest.receipt_count;
            any_truncated |= bundle.manifest.truncated;
            heads.push((bundle.manifest.agent.clone(), bundle.manifest.head.clone()));
            for entry in &bundle.receipts {
                leaves.push(crate::merkle::leaf_for_receipt(&entry.receipt)?);
            }
        }
        let root = crate::merkle::MerkleTree::new(leaves).root();

        let mut manifest = crate::export::TenantExportManifest {
            version: crate::export::EXPORT_VERSION,
            tenant: tenant.to_string(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            agent_count: bundles.len() as u64,
            receipt_count: total,
            merkle_root: format!("0x{}", hex::encode(root)),
            agent_heads: heads,
            signer: self.signer.address_hex(),
            signature: String::new(),
            tenant_signer: None,
            tenant_signature: None,
            truncated: any_truncated,
            key_events_digest: None,
            checkpoints_digest: None,
            policies_digest: None,
        };

        let cosigner = self.tenant_cosigner(tenant).await?;
        if let Some(cosigner) = &cosigner {
            manifest.tenant_signer = Some(cosigner.address_hex());
        }
        let digest = crate::export::tenant_manifest_digest(&manifest)?;
        manifest.signature = self.signer.sign_hash(&digest).await?;
        if let Some(cosigner) = &cosigner {
            let (r, s, recid) =
                crate::signer::DigestSigner::sign_prehash(cosigner.as_ref(), &digest).await?;
            manifest.tenant_signature = Some(Self::signature_hex(r, s, recid));
        }

        let anchors = self
            .anchors
            .list(tenant)
            .await?
            .into_iter()
            .filter_map(|record| serde_json::to_value(record).ok())
            .collect();

        // Carry the key-event ledger and the checkpoints so the archive is self-contained.
        let key_events = self.key_events.list(tenant).await?;
        let checkpoints = self.chain_checkpoints.list(tenant).await?;
        let policies = self.policies.versions(tenant).await?;
        if !key_events.is_empty() {
            manifest.key_events_digest = Some(crate::export::digest_of(&key_events)?);
        }
        if !checkpoints.is_empty() {
            manifest.checkpoints_digest = Some(crate::export::digest_of(&checkpoints)?);
        }
        if !policies.is_empty() {
            manifest.policies_digest = Some(crate::export::digest_of(&policies)?);
        }
        // Re-sign: the digests are covered by the tenant + broker signatures.
        let digest = crate::export::tenant_manifest_digest(&manifest)?;
        manifest.signature = self.signer.sign_hash(&digest).await?;
        manifest.tenant_signature = None;
        if let Some(cosigner) = &cosigner {
            let (r, s, recid) =
                crate::signer::DigestSigner::sign_prehash(cosigner.as_ref(), &digest).await?;
            manifest.tenant_signature = Some(Self::signature_hex(r, s, recid));
        }

        crate::metrics::export_bundle();
        Ok(crate::export::TenantExportBundle {
            manifest,
            agents: bundles,
            anchors,
            key_events,
            checkpoints,
            policies,
        })
    }

    /// Revoke an agent or a grant, and attempt provider-side invalidation for grants.
    pub async fn revoke(
        &self,
        tenant: &str,
        target: &str,
        kind: &str,
        reason: Option<String>,
    ) -> Result<RevokeOutcome, BrokerError> {
        let event = self
            .revocations
            .revoke(tenant, target, kind, reason.clone())
            .await?;
        crate::metrics::revocation();
        let mut provider = None;
        let mut capability = None;
        let mut grant_revoked = None;
        let mut credential_revoked = None;
        if kind == "grant" {
            if let Some(p) = crate::issuers::grant_provider(target) {
                provider = Some(p.to_string());
                capability = Some(provider_capability(p).to_string());
                if let Some(issuer) = self.issuers.get(p) {
                    grant_revoked =
                        Some(issuer.revoke_grant(tenant, target).await.unwrap_or(false));
                }
            }
        } else if kind == "credential" {
            if let Some(p) = crate::issuers::credential_provider(target) {
                provider = Some(p.to_string());
                capability = Some(provider_capability(p).to_string());
                if let Some(issuer) = self.issuers.get(p) {
                    let effect = issuer.revoke_credential(tenant, target).await?;
                    credential_revoked = Some(effect == crate::issuers::RevokeEffect::Revoked);
                }
            }
        }
        let details = serde_json::json!({
            "transitionType": "authority.revoked",
            "target": target,
            "kind": kind,
            "reason": reason,
            "provider": provider,
            "capability": capability,
            "grantRevoked": grant_revoked,
            "credentialRevoked": credential_revoked,
        });
        if let Err(e) = self
            .append_ledger_event(tenant, "authority.revoked", target, target, "", details)
            .await
        {
            tracing::warn!(tenant = %tenant, target = %target, "authority transition append failed: {e}");
        }
        Ok(RevokeOutcome {
            event,
            provider,
            capability,
            grant_revoked,
            credential_revoked,
        })
    }

    /// Build a Merkle anchor batch over an agent's current chain (root + calldata).
    pub async fn anchor_batch(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<AnchorBatch, BrokerError> {
        let chain = self.chain.chain(tenant, agent).await?;
        let mut leaves = Vec::with_capacity(chain.len());
        for entry in &chain {
            leaves.push(merkle::leaf_for_receipt(&entry.receipt)?);
        }
        let tenant_hash = merkle::keccak(tenant.as_bytes());
        Ok(merkle::build_batch(tenant_hash, leaves))
    }

    /// Return an agent's chain for a tenant (chains are tenant-scoped, so no ownership check
    /// is needed: another tenant's chain is simply a different, empty chain).
    pub async fn chain_entries(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Vec<ChainEntry>, BrokerError> {
        self.chain.chain(tenant, agent).await
    }

    /// Run retention: prune terminal anchors and idle telemetry older than `days`.
    pub async fn run_retention(&self, days: u64) -> Result<(u64, u64), BrokerError> {
        if days == 0 {
            return Ok((0, 0));
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let anchors = self.anchors.prune_before(cutoff).await?;
        let telemetry = self.telemetry.prune_idle_before(cutoff).await?;
        if anchors > 0 || telemetry > 0 {
            tracing::info!(anchors, telemetry, days, "retention swept");
        }
        Ok((anchors, telemetry))
    }

    /// Propose a least-privilege policy from the tenant's telemetry graph.
    pub async fn propose_policy(&self, tenant: &str) -> Result<ProposedPolicy, BrokerError> {
        let stats = self.telemetry.stats(tenant).await?;
        Ok(crate::telemetry::propose(&stats))
    }

    /// Store a tenant anchor target, encrypting its private key at rest.
    pub async fn set_anchor_target(
        &self,
        tenant: &str,
        mut target: AnchorTarget,
    ) -> Result<AnchorTarget, BrokerError> {
        self.rpc_policy.validate(&target.rpc_url)?;

        // Rotation: keep the address of the previously configured key so verifiers can keep
        // accepting artifacts it co-signed. Callers cannot set history directly.
        let previous = self.anchor_targets.get(tenant).await?;
        let mut history = previous
            .as_ref()
            .map(|prior| prior.signer_history.clone())
            .unwrap_or_default();
        if let Some(prior) = &previous {
            if let Some(stored) = prior.private_key.as_deref() {
                if let Ok(plaintext) = self.private_key_plaintext(stored) {
                    if let Ok(signer) = crate::signer::LocalSigner::from_hex(&plaintext) {
                        let address = crate::signer::DigestSigner::address_hex(&signer);
                        if !history.iter().any(|h| h.eq_ignore_ascii_case(&address)) {
                            history.push(address);
                        }
                    }
                }
            }
        }
        target.signer_history = history;

        target.private_key = match target.private_key.take() {
            None => None,
            Some(key) if key.trim().is_empty() => None,
            Some(key) => {
                let envelope = self.secrets.as_ref().ok_or_else(|| {
                    BrokerError::NotConfigured(
                        "TENANT_SECRET_ENC_KEY must be set to store a tenant signing key".into(),
                    )
                })?;
                Some(envelope.encrypt(&key)?)
            }
        };

        // The new key must not collide with history (a rotated-back key would be ambiguous).
        if let Some(stored) = target.private_key.as_deref() {
            let plaintext = self.private_key_plaintext(stored)?;
            let signer = crate::signer::LocalSigner::from_hex(&plaintext)?;
            let address = crate::signer::DigestSigner::address_hex(&signer);
            target
                .signer_history
                .retain(|h| !h.eq_ignore_ascii_case(&address));
        }

        self.anchor_targets.set(tenant, target.clone()).await?;
        Ok(target)
    }

    /// Decrypt a stored tenant key (legacy plaintext values are returned as-is).
    fn private_key_plaintext(&self, stored: &str) -> Result<String, BrokerError> {
        if is_encrypted(stored) {
            let envelope = self.secrets.as_ref().ok_or_else(|| {
                BrokerError::NotConfigured(
                    "TENANT_SECRET_ENC_KEY missing but the stored anchor key is encrypted".into(),
                )
            })?;
            envelope.decrypt(stored)
        } else {
            Ok(stored.to_string())
        }
    }

    /// Address of the signer that would submit this tenant's anchors (resolves the key, so it
    /// also proves the stored key is usable).
    pub async fn anchor_signer_address(&self, tenant: &str) -> Result<String, BrokerError> {
        let submitter = self.submitter_for(self.anchor_targets.get(tenant).await?)?;
        Ok(submitter.signer_address())
    }

    /// Resolve the submitter for a tenant (per-tenant target or the global default).
    fn submitter_for(
        &self,
        target: Option<AnchorTarget>,
    ) -> Result<Arc<AnchorSubmitter>, BrokerError> {
        match target {
            Some(t) => match &t.private_key {
                Some(stored) => {
                    let key = self.private_key_plaintext(stored)?;
                    Ok(Arc::new(AnchorSubmitter::new(
                        &t.rpc_url,
                        &key,
                        &t.contract,
                    )?))
                }
                None => {
                    let global = self.anchor.as_ref().ok_or_else(|| {
                        BrokerError::NotConfigured("on-chain anchoring is not configured".into())
                    })?;
                    Ok(Arc::new(global.rebind(&t.rpc_url, &t.contract)?))
                }
            },
            None => self.anchor.clone().ok_or_else(|| {
                BrokerError::NotConfigured("on-chain anchoring is not configured".into())
            }),
        }
    }

    /// Submit the tenant's agent chain root and persist an anchor record.
    pub async fn submit_anchor(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<AnchorRecord, BrokerError> {
        self.anchor_and_record(tenant, agent, true)
            .await?
            .ok_or_else(|| BrokerError::Invalid("chain is empty; nothing to anchor".into()))
    }

    /// Build and submit an anchor for a chain; record it. Returns `None` when there is
    /// nothing new to anchor (empty chain, or unchanged root unless `force`).
    pub async fn anchor_and_record(
        &self,
        tenant: &str,
        agent: &str,
        force: bool,
    ) -> Result<Option<AnchorRecord>, BrokerError> {
        // Check what there is to anchor before requiring a configured submitter, so an empty
        // or unchanged chain reports "nothing to do" rather than "not configured".
        let batch = self.anchor_batch(tenant, agent).await?;
        if batch.count == 0 {
            return Ok(None);
        }
        if !force {
            if let Some(last) = self.anchors.latest(tenant, agent).await? {
                // Skip when the root is unchanged *and* the last record is still live; a
                // failed or reorged anchor must be retried.
                let live = !matches!(last.status.as_str(), "failed" | "reorged");
                if last.merkle_root == batch.root && live {
                    return Ok(None);
                }
            }
        }

        let target = self.anchor_targets.get(tenant).await?;
        // Prefer the tenant target's declared chain id: it is what verifiers will use.
        let target_chain_id = target.as_ref().map(|t| t.chain_id).unwrap_or(0);
        let submitter = self.submitter_for(target)?;
        let chain_id = if target_chain_id != 0 {
            target_chain_id
        } else if submitter.chain_id() != 0 {
            submitter.chain_id()
        } else {
            self.signer.domain().chain_id
        };
        let contract = submitter.contract_hex();

        // Claim the (tenant, agent, root) submission so another replica or a concurrent call
        // cannot submit the same root twice.
        let claim_id = match self
            .anchors
            .claim(tenant, agent, &batch.root, batch.count, chain_id, &contract)
            .await?
        {
            ClaimOutcome::AlreadyClaimed => return Ok(None),
            ClaimOutcome::Claimed { id } => id,
        };

        self.egress.check_resolved(submitter.rpc_url()).await?;
        let root = parse_hex32(&batch.root)?;
        let tenant_hash = merkle::keccak(tenant.as_bytes());
        let tx_hash = match submitter.submit(tenant_hash, root, batch.count).await {
            Ok(hash) => {
                crate::metrics::anchor_submission();
                hash
            }
            Err(e) => {
                crate::metrics::anchor_failure();
                // Release the claim so a later attempt can re-claim.
                let _ = self.anchors.update(tenant, &claim_id, "failed", None).await;
                return Err(e);
            }
        };

        // Best-effort confirmation (bounded). Unconfirmed txs stay "submitted"; a reverted
        // tx is recorded as "failed".
        let confirmation = submitter.confirm(&tx_hash, 15).await.unwrap_or(None);
        let (status, block_number) = match confirmation {
            Some((true, block)) => ("confirmed", Some(block)),
            Some((false, _)) => ("failed", None),
            None => ("submitted", None),
        };
        self.anchors
            .settle(tenant, &claim_id, &tx_hash, status, block_number)
            .await?;

        let record = self
            .anchors
            .latest(tenant, agent)
            .await?
            .ok_or_else(|| BrokerError::Internal("settled anchor record missing".into()))?;
        Ok(Some(record))
    }

    /// Re-check pending anchors for a tenant: update status/block, and re-anchor any whose
    /// transaction has been reorged out of the canonical chain.
    pub async fn reconfirm_anchors(&self, tenant: &str) -> Result<usize, BrokerError> {
        use crate::anchoring::{plan_reconfirmation, ReconfirmAction};

        let target = self.anchor_targets.get(tenant).await?;
        let submitter = match self.submitter_for(target) {
            Ok(s) => s,
            Err(_) => return Ok(0),
        };

        let head = submitter.head_block().await.unwrap_or(0);
        let now = chrono::Utc::now();
        let pending = self.anchors.pending(tenant).await?;
        let mut updated = 0usize;

        for anchor in pending {
            let observation = match &anchor.tx_hash {
                Some(tx) => submitter.observe(tx).await.ok().flatten(),
                None => None,
            };
            match plan_reconfirmation(
                &anchor,
                observation,
                head,
                self.anchor_confirmations,
                now,
                self.anchor_reorg_grace_secs,
            ) {
                ReconfirmAction::Keep => {}
                ReconfirmAction::Update {
                    status,
                    block_number,
                } => {
                    self.anchors
                        .update(tenant, &anchor.id, &status, block_number)
                        .await?;
                    updated += 1;
                }
                ReconfirmAction::Reanchor => {
                    self.anchors
                        .update(tenant, &anchor.id, "reorged", None)
                        .await?;
                    crate::metrics::anchor_failure();
                    tracing::warn!(
                        tenant = %tenant,
                        agent = %anchor.agent,
                        tx = ?anchor.tx_hash,
                        "anchor reorged; re-anchoring"
                    );
                    match self.anchor_and_record(tenant, &anchor.agent, true).await {
                        Ok(Some(_)) => updated += 1,
                        Ok(None) => {}
                        Err(e) => tracing::warn!(tenant = %tenant, "re-anchor failed: {e}"),
                    }
                }
            }
        }
        Ok(updated)
    }

    /// Set `prev` from the current head, sign, append; retry on optimistic conflicts.
    async fn append(
        &self,
        tenant: &str,
        agent: &str,
        mut receipt: GrantReceipt,
    ) -> Result<ChainEntry, BrokerError> {
        let chain_lock = agent_chain_lock(tenant, agent);
        let _chain_guard = chain_lock.lock().await;
        for attempt in 0..64 {
            let head = self.chain.head_hash(tenant, agent).await?;
            receipt.prev = head;
            self.signer.sign(&mut receipt).await?;
            let entry = ChainEntry {
                payload_hash: crate::receipt::payload_hash_hex(&receipt)?,
                receipt: receipt.clone(),
            };
            if self.chain.append(tenant, agent, entry.clone()).await? == AppendOutcome::Appended {
                return Ok(entry);
            }
            tokio::time::sleep(std::time::Duration::from_millis(1 + (attempt % 5) as u64)).await;
        }
        Err(BrokerError::Internal(
            "receipt chain append contention".into(),
        ))
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], BrokerError> {
    let raw = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Internal(format!("bad hex32: {e}")))?;
    if raw.len() != 32 {
        return Err(BrokerError::Internal(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn now_ts() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn principal_from(req: &AuthorizeRequest) -> PrincipalRef {
    match &req.principal {
        Some(p) => PrincipalRef {
            principal_id: p.principal_id.clone(),
            principal_type: p
                .principal_type
                .clone()
                .unwrap_or_else(|| "user".to_string()),
            authority_ref: p.authority_ref.clone(),
            authority_hash: p.authority_hash.clone(),
            verified_at: p.verified_at.clone().or_else(|| Some(now_ts())),
            verification_method: p
                .verification_method
                .clone()
                .unwrap_or_else(|| "caller".to_string()),
        },
        None => PrincipalRef {
            principal_id: req.user_id.clone(),
            principal_type: "user".to_string(),
            authority_ref: req.user_id.clone(),
            authority_hash: canonical::keccak256_str(&req.user_id),
            verified_at: Some(now_ts()),
            verification_method: "user_id".to_string(),
        },
    }
}

fn agent_meta_from(req: &AuthorizeRequest) -> AgentRef {
    let meta = req.agent_meta.clone();
    AgentRef {
        agent_id: req.agent_id.clone(),
        agent_version: meta.as_ref().and_then(|m| m.agent_version.clone()),
        model_id: meta.as_ref().and_then(|m| m.model_id.clone()),
        operator_id: meta.as_ref().and_then(|m| m.operator_id.clone()),
        environment: meta.as_ref().and_then(|m| m.environment.clone()),
    }
}

fn policy_ref(
    decision: &crate::policy::PolicyResult,
    agent_id: &str,
    user_id: &str,
    resource: &str,
    args_hash: &str,
) -> PolicyRef {
    let evaluated_inputs_hash = canonical::hash_json(&serde_json::json!({
        "agentId": agent_id,
        "userId": user_id,
        "resource": resource,
        "argsHash": args_hash,
    }));
    PolicyRef {
        policy_id: decision.policy_id.clone(),
        policy_version: decision.policy_version,
        policy_hash: decision
            .policy_hash
            .clone()
            .unwrap_or_else(|| canonical::keccak256_str("no-matching-policy")),
        decision: if decision.allow { "allow" } else { "deny" }.to_string(),
        reason_code: Some(decision.reason.chars().take(512).collect()),
        evaluated_inputs_hash: Some(evaluated_inputs_hash),
        evaluator_version: Some("tessera-policy-v1".to_string()),
    }
}

fn credential_ref(credential: &EphemeralCredential, scopes: &[String]) -> CredentialRef {
    let credential_type = match &credential.material {
        CredentialMaterial::AwsSts { .. } => "aws_sts",
        CredentialMaterial::Bearer { .. } => "bearer",
        CredentialMaterial::Grant { .. } => "broker_grant",
    }
    .to_string();
    // Never derive a receipt field from a bearer secret. Prefer the issuer's non-secret
    // reference or issuance id; fall back to a random issuance id for opaque tokens.
    let issuance_id =
        credential
            .issuance_id
            .clone()
            .unwrap_or_else(|| match &credential.material {
                CredentialMaterial::AwsSts { access_key_id, .. } => access_key_id.clone(),
                CredentialMaterial::Bearer { .. } => credential
                    .reference
                    .clone()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                CredentialMaterial::Grant { grant_id, .. } => grant_id.clone(),
            });
    let thumbprint = canonical::hash_json(&serde_json::json!({
        "provider": credential.provider,
        "resource": credential.resource,
        "ttlSeconds": credential.ttl_seconds,
        "singleUse": credential.single_use,
        "argsHash": credential.args_hash,
        "issuanceId": issuance_id,
    }));
    CredentialRef {
        issuer: credential.provider.clone(),
        credential_type,
        thumbprint,
        scopes: scopes.to_vec(),
        ttl_seconds: credential.ttl_seconds,
        single_use: credential.single_use,
        issuance_id,
    }
}

fn attestation_ref(signer: &ReceiptSigner) -> AttestationRef {
    AttestationRef {
        signer_key_id: signer.address_hex(),
        signature_alg: "secp256k1-eip712".to_string(),
        timestamp: Some(now_ts()),
        transparency_log_index: None,
        anchor_ref: None,
    }
}

fn normalize_outcome_status(status: Option<&str>) -> String {
    match status
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("success") | Some("succeeded") | Some("ok") | Some("used") => "success".to_string(),
        Some("failure") | Some("failed") | Some("error") => "failure".to_string(),
        Some("denied") => "denied".to_string(),
        Some("timeout") | Some("timed_out") => "timeout".to_string(),
        Some("") | None => "unknown".to_string(),
        Some(_) => "unknown".to_string(),
    }
}

fn validate_authorize_input(req: &AuthorizeRequest) -> Result<(), BrokerError> {
    valid_len(&req.tool, "tool", 1, 256)?;
    valid_len(&req.user_id, "userId", 1, 256)?;
    if req.intent.len() > 8_192 {
        return Err(BrokerError::Invalid("intent exceeds 8192 bytes".into()));
    }
    if let Some(token) = &req.authority_token {
        valid_len(token, "authorityToken", 1, 8_192)?;
    }
    if let Some(hash) = req.tool_schema_hash.as_deref() {
        if !valid_hash(hash) {
            return Err(BrokerError::Invalid(
                "toolSchemaHash must be a 32-byte hex hash".into(),
            ));
        }
    }
    if let Some(principal) = &req.principal {
        valid_len(&principal.principal_id, "principalId", 1, 256)?;
        valid_len(&principal.authority_ref, "authorityRef", 1, 512)?;
        if !valid_hash(&principal.authority_hash) {
            return Err(BrokerError::Invalid(
                "authorityHash must be a 32-byte hex hash".into(),
            ));
        }
        if let Some(kind) = &principal.principal_type {
            valid_len(kind, "principalType", 1, 64)?;
        }
        if let Some(method) = &principal.verification_method {
            valid_len(method, "verificationMethod", 1, 64)?;
        }
        if let Some(verified_at) = &principal.verified_at {
            valid_len(verified_at, "verifiedAt", 1, 64)?;
            if chrono::DateTime::parse_from_rfc3339(verified_at).is_err() {
                return Err(BrokerError::Invalid("verifiedAt must be RFC 3339".into()));
            }
        }
    }
    if let Some(meta) = &req.agent_meta {
        for (value, field) in [
            (&meta.agent_version, "agentVersion"),
            (&meta.model_id, "modelId"),
            (&meta.operator_id, "operatorId"),
            (&meta.environment, "environment"),
        ] {
            if let Some(value) = value {
                valid_len(value, field, 1, 256)?;
            }
        }
    }
    if let Some(scopes) = &req.requested_scopes {
        if scopes.len() > 64 {
            return Err(BrokerError::Invalid(
                "requestedScopes exceeds 64 entries".into(),
            ));
        }
        for scope in scopes {
            valid_len(scope, "requestedScopes[]", 1, 256)?;
        }
    }
    if let Some(risk) = &req.risk_class {
        valid_len(risk, "riskClass", 1, 64)?;
    }
    if let Some(purpose) = &req.declared_purpose {
        valid_len(purpose, "declaredPurpose", 1, 1024)?;
    }
    Ok(())
}

fn valid_len(value: &str, field: &str, min: usize, max: usize) -> Result<(), BrokerError> {
    if value.len() < min || value.len() > max {
        return Err(BrokerError::Invalid(format!(
            "{field} must be {min}..={max} bytes"
        )));
    }
    Ok(())
}

fn valid_hash(value: &str) -> bool {
    let raw = value.trim_start_matches("0x");
    raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_record_input(req: &RecordRequest) -> Result<(), BrokerError> {
    if !valid_hash(&req.result_hash) {
        return Err(BrokerError::Invalid(
            "resultHash must be a 32-byte hex hash".into(),
        ));
    }
    if let Some(error_class) = &req.error_class {
        valid_len(error_class, "errorClass", 1, 128)?;
    }
    if let Some(external_ref) = &req.external_ref {
        valid_len(external_ref, "externalRef", 1, 512)?;
    }
    if let Some(raw) = &req.completed_at {
        valid_len(raw, "completedAt", 1, 64)?;
        let parsed = chrono::DateTime::parse_from_rfc3339(raw)
            .map_err(|_| BrokerError::Invalid("completedAt must be RFC 3339".into()))?;
        let delta = chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc));
        if delta.num_seconds().abs() > 86_400 {
            return Err(BrokerError::Invalid(
                "completedAt must be within 24 hours of now".into(),
            ));
        }
    }
    Ok(())
}
