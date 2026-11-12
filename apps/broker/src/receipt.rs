//! Signed grant receipts.
//!
//! A receipt is the tamper-evident record of an authorization decision (and, later, its
//! outcome). It is signed with EIP-712 over a compact digest of the canonical payload,
//! mirroring the authorization-grant pattern used elsewhere in the stack.
//!
//! EIP-712 struct:
//!   Receipt(bytes32 payloadHash, bytes32 prev, bytes32 agentIdHash, bytes32 nonce)

use std::sync::Arc;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use crate::canonical;
use crate::error::BrokerError;
use crate::signer::{DigestSigner, LocalSigner};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrantReceipt {
    pub v: u8,
    pub tenant: String,
    pub agent: String,
    pub user: String,
    pub intent_hash: String,
    pub authorization: AuthorizationRef,
    pub call: CallRef,
    pub grant: GrantRef,
    pub ts: String,
    pub nonce: String,
    pub prev: Option<String>,
    /// The authorization receipt this outcome belongs to. Outcomes may follow a later
    /// chain head, so this is the durable link; `prev` remains the chain predecessor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_receipt_id: Option<String>,
    pub signature: Option<String>,
    /// Stable id shared by the authorization record and its outcome record (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    /// The human/org on whose authority the agent acts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalRef>,
    /// Agent identity metadata independent of the chain key (`agent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_meta: Option<AgentRef>,
    /// Structured intent metadata (the hash remains in `intentHash`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<IntentRef>,
    /// The exact policy content that produced the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,
    /// The issued credential and its non-secret fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialRef>,
    /// Post-execution outcome; absent on a pre-execution authorization record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OutcomeRef>,
    /// Signer/key metadata for portable verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationRef {
    pub decision: String,
    pub policy: String,
    pub policy_version: u32,
    pub resource: String,
    pub anomaly_score: f64,
    /// Canonical hash of the evaluated policy content (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallRef {
    pub tool: String,
    pub args_hash: String,
    pub result_hash: Option<String>,
    /// Tool-definition hash presented at authorization (pinned tools only). Optional and
    /// omitted when absent, so pre-existing receipts hash identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrantRef {
    pub provider: String,
    pub ttl_s: u32,
    pub single_use: bool,
    pub status: String,
}

/// The delegating human or organization. `authority_ref` names the consent, OAuth grant,
/// mandate, or ticket; `authority_hash` commits to the authority artifact without storing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalRef {
    pub principal_id: String,
    pub principal_type: String,
    pub authority_ref: String,
    pub authority_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    pub verification_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentRef {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IntentRef {
    pub intent_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRef {
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_hash: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_inputs_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRef {
    pub issuer: String,
    pub credential_type: String,
    pub thumbprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    pub ttl_seconds: u32,
    pub single_use: bool,
    pub issuance_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeRef {
    pub status: String,
    /// Who observed the outcome: the broker (proxy mode) or the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    pub completed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationRef {
    pub signer_key_id: String,
    pub signature_alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
}

/// Signs and verifies receipts with a secp256k1 key.
/// EIP-712 domain parameters. Verification needs only this (not the signing key).
#[derive(Debug, Clone, Copy)]
pub struct Domain {
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
    /// EIP-712 domain version. V2 records use `"2"` so a v1 verifier cannot silently accept
    /// an unknown schema under the same digest space.
    pub version: &'static str,
}

impl Domain {
    pub fn new(chain_id: u64, contract: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            chain_id,
            verifying_contract: parse_address(contract)?,
            version: "1",
        })
    }

    pub fn with_version(mut self, version: &'static str) -> Self {
        self.version = version;
        self
    }

    /// Select the domain version for a receipt's schema version.
    fn for_receipt(self, receipt: &GrantReceipt) -> Self {
        self.with_version(if receipt.v >= 2 { "2" } else { "1" })
    }

    pub fn contract_hex(&self) -> String {
        format!("0x{}", hex::encode(self.verifying_contract))
    }
}

pub struct ReceiptSigner {
    backend: Arc<dyn DigestSigner>,
    domain: Domain,
    deterministic: bool,
}

impl ReceiptSigner {
    /// Build a signer from a 32-byte hex key. Falls back to a random key if `None`.
    pub fn from_hex_or_random(
        key_hex: Option<&str>,
        chain_id: u64,
        contract: &str,
    ) -> Result<Self, BrokerError> {
        let (backend, deterministic): (Arc<dyn DigestSigner>, bool) = match key_hex {
            Some(hex_str) => {
                let stripped = hex_str.trim_start_matches("0x");
                if !stripped.is_empty() && stripped.chars().any(|c| c != '0') {
                    (Arc::new(LocalSigner::from_hex(hex_str)?), true)
                } else {
                    (Arc::new(LocalSigner::random()), false)
                }
            }
            None => (Arc::new(LocalSigner::random()), false),
        };
        Self::with_backend(backend, chain_id, contract, deterministic)
    }

    /// Build a signer over an arbitrary signing backend (e.g. a KMS/HSM bridge).
    pub fn with_backend(
        backend: Arc<dyn DigestSigner>,
        chain_id: u64,
        contract: &str,
        deterministic: bool,
    ) -> Result<Self, BrokerError> {
        Ok(Self {
            backend,
            domain: Domain::new(chain_id, contract)?,
            deterministic,
        })
    }

    /// Whether the signer is backed by a stable key (configured or KMS) rather than a
    /// randomly generated dev key.
    pub fn is_deterministic(&self) -> bool {
        self.deterministic
    }

    pub fn address_hex(&self) -> String {
        self.backend.address_hex()
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// Compute and attach the EIP-712 signature.
    pub async fn sign(&self, receipt: &mut GrantReceipt) -> Result<(), BrokerError> {
        let digest = digest(&self.domain, receipt)?;
        let (r, s, recid) = self.backend.sign_prehash(&digest).await?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&r);
        out.extend_from_slice(&s);
        out.push(recid + 27);
        receipt.signature = Some(format!("0x{}", hex::encode(out)));
        Ok(())
    }

    /// Sign an arbitrary 32-byte digest with the broker key (used for audit-export
    /// manifests, which are not receipts).
    pub async fn sign_hash(&self, digest: &[u8; 32]) -> Result<String, BrokerError> {
        let (r, s, recid) = self.backend.sign_prehash(digest).await?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&r);
        out.extend_from_slice(&s);
        out.push(recid + 27);
        Ok(format!("0x{}", hex::encode(out)))
    }

    /// Recover the signer address from a receipt's signature.
    pub fn recover(&self, receipt: &GrantReceipt) -> Result<String, BrokerError> {
        recover(&self.domain, receipt)
    }

    /// Verify that the receipt was signed by `expected_address`.
    pub fn verify(
        &self,
        receipt: &GrantReceipt,
        expected_address: &str,
    ) -> Result<bool, BrokerError> {
        let recovered = recover(&self.domain, receipt)?;
        Ok(recovered.eq_ignore_ascii_case(expected_address))
    }
}

/// Compute the EIP-712 digest for a receipt under `domain` (no key required).
pub fn digest(domain: &Domain, receipt: &GrantReceipt) -> Result<[u8; 32], BrokerError> {
    let domain = domain.for_receipt(receipt);
    let payload = payload_hash(receipt)?;
    let agent_id_hash = canonical::keccak256_str(&receipt.agent);
    let prev = match &receipt.prev {
        Some(p) => parse_bytes32(p)?,
        None => [0u8; 32],
    };
    let nonce = parse_bytes32(&receipt.nonce)?;

    let struct_hash = keccak(
        &[
            receipt_typehash().as_slice(),
            payload.as_slice(),
            prev.as_slice(),
            hex_to_32(&agent_id_hash)?.as_slice(),
            nonce.as_slice(),
        ]
        .concat(),
    );
    let separator = domain_separator(&domain);

    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&separator);
    buf.extend_from_slice(&struct_hash);
    Ok(keccak(&buf))
}

/// Recover the signer address without holding the key (only the domain is needed).
pub fn recover(domain: &Domain, receipt: &GrantReceipt) -> Result<String, BrokerError> {
    let sig_hex = receipt
        .signature
        .as_ref()
        .ok_or_else(|| BrokerError::Receipt("receipt is unsigned".into()))?;
    let raw = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Receipt(format!("bad signature hex: {e}")))?;
    if raw.len() != 65 {
        return Err(BrokerError::Receipt("signature must be 65 bytes".into()));
    }
    let signature = Signature::from_slice(&raw[..64])
        .map_err(|e| BrokerError::Receipt(format!("bad signature: {e}")))?;
    if signature.normalize_s().is_some() {
        return Err(BrokerError::Receipt(
            "signature is not low-S (malleable)".into(),
        ));
    }
    let recid = RecoveryId::from_byte(raw[64].saturating_sub(27))
        .ok_or_else(|| BrokerError::Receipt("bad recovery id".into()))?;
    let digest = digest(domain, receipt)?;
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
        .map_err(|e| BrokerError::Receipt(format!("recover failed: {e}")))?;
    Ok(format!("0x{}", hex::encode(address_of(&vk))))
}

/// Verify a receipt's signature against an expected address without the signing key.
pub fn verify(
    domain: &Domain,
    receipt: &GrantReceipt,
    expected_address: &str,
) -> Result<bool, BrokerError> {
    Ok(recover(domain, receipt)?.eq_ignore_ascii_case(expected_address))
}

/// Recover the address that signed a raw 32-byte digest (audit-export manifests).
pub fn recover_hash(digest: &[u8; 32], sig_hex: &str) -> Result<String, BrokerError> {
    let raw = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Receipt(format!("bad signature hex: {e}")))?;
    if raw.len() != 65 {
        return Err(BrokerError::Receipt("signature must be 65 bytes".into()));
    }
    let signature = Signature::from_slice(&raw[..64])
        .map_err(|e| BrokerError::Receipt(format!("bad signature: {e}")))?;
    if signature.normalize_s().is_some() {
        return Err(BrokerError::Receipt(
            "signature is not low-S (malleable)".into(),
        ));
    }
    let recid = RecoveryId::from_byte(raw[64].saturating_sub(27))
        .ok_or_else(|| BrokerError::Receipt("bad recovery id".into()))?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature, recid)
        .map_err(|e| BrokerError::Receipt(format!("recover failed: {e}")))?;
    Ok(format!("0x{}", hex::encode(address_of(&vk))))
}

fn domain_separator(domain: &Domain) -> [u8; 32] {
    let domain_typehash = keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name = keccak(b"TesseraReceipt");
    let version = keccak(domain.version.as_bytes());
    let mut chain_word = [0u8; 32];
    chain_word[24..].copy_from_slice(&domain.chain_id.to_be_bytes());
    let mut contract_word = [0u8; 32];
    contract_word[12..].copy_from_slice(&domain.verifying_contract);
    keccak(
        &[
            domain_typehash.as_slice(),
            name.as_slice(),
            version.as_slice(),
            chain_word.as_slice(),
            contract_word.as_slice(),
        ]
        .concat(),
    )
}

/// `keccak256(canonical_json(receipt without signature))`.
pub fn payload_hash(receipt: &GrantReceipt) -> Result<[u8; 32], BrokerError> {
    let mut value = serde_json::to_value(receipt)
        .map_err(|e| BrokerError::Receipt(format!("serialize failed: {e}")))?;
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical_json = canonical::canonicalize(&value);
    Ok(keccak(canonical_json.as_bytes()))
}

fn receipt_typehash() -> [u8; 32] {
    keccak(b"Receipt(bytes32 payloadHash,bytes32 prev,bytes32 agentIdHash,bytes32 nonce)")
}

/// Convenience for callers that want the hex payload hash.
pub fn payload_hash_hex(receipt: &GrantReceipt) -> Result<String, BrokerError> {
    Ok(format!("0x{}", hex::encode(payload_hash(receipt)?)))
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn address_of(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn parse_bytes32(s: &str) -> Result<[u8; 32], BrokerError> {
    let raw = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Receipt(format!("bad bytes32: {e}")))?;
    if raw.len() != 32 {
        return Err(BrokerError::Receipt(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

fn hex_to_32(s: &str) -> Result<[u8; 32], BrokerError> {
    parse_bytes32(s)
}

fn parse_address(s: &str) -> Result<[u8; 20], BrokerError> {
    let raw = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Receipt(format!("bad address: {e}")))?;
    if raw.len() != 20 {
        return Err(BrokerError::Receipt(format!(
            "expected 20 bytes, got {}",
            raw.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

/// Build a receipt with a random nonce and the current timestamp (RFC 3339).
pub fn new_receipt(
    tenant: &str,
    agent: &str,
    user: &str,
    intent_hash: String,
    authorization: AuthorizationRef,
    call: CallRef,
    grant: GrantRef,
) -> GrantReceipt {
    GrantReceipt {
        v: 1,
        tenant: tenant.to_string(),
        agent: agent.to_string(),
        user: user.to_string(),
        intent_hash,
        authorization,
        call,
        grant,
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        nonce: {
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            format!("0x{}", hex::encode(nonce))
        },
        prev: None,
        authorization_receipt_id: None,
        signature: None,
        action_id: None,
        principal: None,
        agent_meta: None,
        intent: None,
        policy: None,
        credential: None,
        outcome: None,
        attestation: None,
    }
}

/// Validate the fields a v2 record must carry. V1 records are unaffected.
pub fn validate_v2(receipt: &GrantReceipt) -> Result<(), BrokerError> {
    match receipt.v {
        1 => return Ok(()),
        2 => {}
        other => {
            return Err(BrokerError::Invalid(format!(
                "unsupported receipt version {other}"
            )))
        }
    }
    if receipt.authorization.decision != "allow" && receipt.authorization.decision != "deny" {
        return Err(BrokerError::Invalid(
            "authorization.decision must be allow or deny".into(),
        ));
    }
    if !(0.0..=1.0).contains(&receipt.authorization.anomaly_score) {
        return Err(BrokerError::Invalid(
            "authorization.anomalyScore must be in [0, 1]".into(),
        ));
    }
    require_len(&receipt.tenant, "tenant", 1, 128)?;
    require_len(&receipt.agent, "agent", 1, 128)?;
    require_len(&receipt.user, "user", 1, 256)?;
    require_hash(&receipt.intent_hash, "intentHash")?;
    require_len(&receipt.grant.status, "grant.status", 1, 32)?;
    if !matches!(
        receipt.grant.status.as_str(),
        "issued" | "used" | "denied" | "expired" | "revoked"
    ) {
        return Err(BrokerError::Invalid(
            "grant.status is not recognized".into(),
        ));
    }
    require_len(&receipt.call.tool, "call.tool", 1, 256)?;
    require_hash(&receipt.call.args_hash, "call.argsHash")?;
    require_len(
        &receipt.authorization.resource,
        "authorization.resource",
        1,
        256,
    )?;
    require_hash(&receipt.nonce, "nonce")?;
    if let Some(prev) = receipt.prev.as_deref() {
        require_hash(prev, "prev")?;
    }
    if let Some(authorization_receipt_id) = receipt.authorization_receipt_id.as_deref() {
        require_hash(authorization_receipt_id, "authorizationReceiptId")?;
    }
    if chrono::DateTime::parse_from_rfc3339(&receipt.ts).is_err() {
        return Err(BrokerError::Invalid("ts must be RFC 3339".into()));
    }
    let action_id = receipt
        .action_id
        .as_deref()
        .ok_or_else(|| BrokerError::Invalid("v2 receipt is missing actionId".into()))?;
    require_len(action_id, "actionId", 1, 128)?;

    let principal = receipt
        .principal
        .as_ref()
        .ok_or_else(|| BrokerError::Invalid("v2 receipt is missing principal".into()))?;
    require_len(&principal.principal_id, "principal.principalId", 1, 256)?;
    if receipt.user != principal.principal_id {
        return Err(BrokerError::Invalid(
            "user must match principal.principalId".into(),
        ));
    }
    require_len(&principal.principal_type, "principal.principalType", 1, 64)?;
    require_len(&principal.authority_ref, "principal.authorityRef", 1, 512)?;
    require_len(
        &principal.verification_method,
        "principal.verificationMethod",
        1,
        64,
    )?;
    require_hash(&principal.authority_hash, "principal.authorityHash")?;
    if let Some(verified_at) = &principal.verified_at {
        if chrono::DateTime::parse_from_rfc3339(verified_at).is_err() {
            return Err(BrokerError::Invalid(
                "principal.verifiedAt must be RFC 3339".into(),
            ));
        }
    }

    let agent = receipt
        .agent_meta
        .as_ref()
        .ok_or_else(|| BrokerError::Invalid("v2 receipt is missing agentMeta".into()))?;
    require_len(&agent.agent_id, "agentMeta.agentId", 1, 128)?;
    if agent.agent_id != receipt.agent {
        return Err(BrokerError::Invalid(
            "agentMeta.agentId does not match agent".into(),
        ));
    }
    for (value, field) in [
        (&agent.agent_version, "agentMeta.agentVersion"),
        (&agent.model_id, "agentMeta.modelId"),
        (&agent.operator_id, "agentMeta.operatorId"),
        (&agent.environment, "agentMeta.environment"),
    ] {
        if let Some(value) = value {
            require_len(value, field, 1, 256)?;
        }
    }

    let intent = receipt
        .intent
        .as_ref()
        .ok_or_else(|| BrokerError::Invalid("v2 receipt is missing intent".into()))?;
    require_hash(&intent.intent_hash, "intent.intentHash")?;
    if intent.intent_hash != receipt.intent_hash {
        return Err(BrokerError::Invalid(
            "intent.intentHash does not match intentHash".into(),
        ));
    }
    if intent.requested_scopes.len() > 64 {
        return Err(BrokerError::Invalid(
            "intent.requestedScopes exceeds 64 entries".into(),
        ));
    }
    for scope in &intent.requested_scopes {
        require_len(scope, "intent.requestedScopes[]", 1, 256)?;
    }
    if let Some(risk) = &intent.risk_class {
        require_len(risk, "intent.riskClass", 1, 64)?;
    }
    if let Some(purpose) = &intent.declared_purpose {
        require_len(purpose, "intent.declaredPurpose", 1, 1024)?;
    }

    let policy = receipt
        .policy
        .as_ref()
        .ok_or_else(|| BrokerError::Invalid("v2 receipt is missing policy".into()))?;
    require_hash(&policy.policy_hash, "policy.policyHash")?;
    if let Some(inputs_hash) = &policy.evaluated_inputs_hash {
        require_hash(inputs_hash, "policy.evaluatedInputsHash")?;
    }
    if let Some(reason) = &policy.reason_code {
        require_len(reason, "policy.reasonCode", 1, 512)?;
    }
    if let Some(evaluator) = &policy.evaluator_version {
        require_len(evaluator, "policy.evaluatorVersion", 1, 64)?;
    }
    if policy.decision != receipt.authorization.decision {
        return Err(BrokerError::Invalid(
            "policy.decision does not match authorization.decision".into(),
        ));
    }
    if policy.policy_id != receipt.authorization.policy
        || policy.policy_version != receipt.authorization.policy_version
    {
        return Err(BrokerError::Invalid(
            "policy id/version does not match authorization".into(),
        ));
    }
    match receipt.authorization.policy_hash.as_deref() {
        Some(hash) if hash == policy.policy_hash => {}
        _ => {
            return Err(BrokerError::Invalid(
                "authorization.policyHash does not match policy.policyHash".into(),
            ))
        }
    }

    let attestation = receipt
        .attestation
        .as_ref()
        .ok_or_else(|| BrokerError::Invalid("v2 receipt is missing attestation".into()))?;
    require_len(
        &attestation.signer_key_id,
        "attestation.signerKeyId",
        1,
        256,
    )?;
    require_len(
        &attestation.signature_alg,
        "attestation.signatureAlg",
        1,
        64,
    )?;
    if let Some(timestamp) = &attestation.timestamp {
        if chrono::DateTime::parse_from_rfc3339(timestamp).is_err() {
            return Err(BrokerError::Invalid(
                "attestation.timestamp must be RFC 3339".into(),
            ));
        }
    }

    if receipt.authorization.decision == "allow" {
        let credential = receipt.credential.as_ref().ok_or_else(|| {
            BrokerError::Invalid("allowed v2 receipt is missing credential".into())
        })?;
        require_hash(&credential.thumbprint, "credential.thumbprint")?;
        require_len(&credential.issuance_id, "credential.issuanceId", 1, 256)?;
        require_len(&credential.issuer, "credential.issuer", 1, 128)?;
        require_len(
            &credential.credential_type,
            "credential.credentialType",
            1,
            64,
        )?;
        if credential.issuer != receipt.grant.provider {
            return Err(BrokerError::Invalid(
                "credential.issuer does not match grant.provider".into(),
            ));
        }
        if credential.ttl_seconds != receipt.grant.ttl_s {
            return Err(BrokerError::Invalid(
                "credential.ttlSeconds does not match grant.ttlS".into(),
            ));
        }
        if credential.single_use != receipt.grant.single_use {
            return Err(BrokerError::Invalid(
                "credential.singleUse does not match grant.singleUse".into(),
            ));
        }
        if credential.scopes.len() > 64 {
            return Err(BrokerError::Invalid(
                "credential.scopes exceeds 64 entries".into(),
            ));
        }
        for scope in &credential.scopes {
            require_len(scope, "credential.scopes[]", 1, 256)?;
        }
    }

    if let Some(tool_hash) = &receipt.call.tool_hash {
        require_hash(tool_hash, "call.toolHash")?;
    }
    if let Some(result_hash) = receipt.call.result_hash.as_deref() {
        require_hash(result_hash, "call.resultHash")?;
    }
    if let Some(outcome) = &receipt.outcome {
        require_len(&outcome.status, "outcome.status", 1, 32)?;
        if let Some(source) = &outcome.source {
            if !matches!(source.as_str(), "broker_observed" | "agent_reported") {
                return Err(BrokerError::Invalid(
                    "outcome.source must be broker_observed or agent_reported".into(),
                ));
            }
        }
        if !matches!(
            outcome.status.as_str(),
            "success" | "failure" | "denied" | "timeout" | "unknown"
        ) {
            return Err(BrokerError::Invalid(
                "outcome.status must be success, failure, denied, timeout, or unknown".into(),
            ));
        }
        require_len(&outcome.completed_at, "outcome.completedAt", 1, 64)?;
        if chrono::DateTime::parse_from_rfc3339(&outcome.completed_at).is_err() {
            return Err(BrokerError::Invalid(
                "outcome.completedAt must be RFC 3339".into(),
            ));
        }
        if let Some(error_class) = &outcome.error_class {
            require_len(error_class, "outcome.errorClass", 1, 128)?;
        }
        if let Some(external_ref) = &outcome.external_ref {
            require_len(external_ref, "outcome.externalRef", 1, 512)?;
        }
        if let Some(result_hash) = outcome.result_hash.as_deref() {
            require_hash(result_hash, "outcome.resultHash")?;
            if let Some(call_hash) = receipt.call.result_hash.as_deref() {
                if call_hash != result_hash {
                    return Err(BrokerError::Invalid(
                        "outcome.resultHash does not match call.resultHash".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_len(value: &str, field: &str, min: usize, max: usize) -> Result<(), BrokerError> {
    if value.len() < min || value.len() > max {
        return Err(BrokerError::Invalid(format!(
            "{field} must be {min}..={max} bytes"
        )));
    }
    Ok(())
}

fn require_hash(value: &str, field: &str) -> Result<(), BrokerError> {
    let raw = value.trim_start_matches("0x");
    if raw.len() != 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BrokerError::Invalid(format!(
            "{field} must be a 32-byte hash"
        )));
    }
    Ok(())
}

/// Refresh a receipt's timestamp and nonce and clear its signature (for re-issuing a
/// linked record, e.g. an outcome). The caller must re-sign afterwards.
pub fn restamp(receipt: &mut GrantReceipt) {
    receipt.ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    receipt.nonce = format!("0x{}", hex::encode(nonce));
    receipt.signature = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GrantReceipt {
        new_receipt(
            "tenant_a",
            "agent_1",
            "user_1",
            canonical::keccak256_str("refund a duplicate charge"),
            AuthorizationRef {
                decision: "allow".into(),
                policy: "p1".into(),
                policy_version: 3,
                resource: "stripe:refunds.create".into(),
                anomaly_score: 0.0,
                policy_hash: None,
            },
            CallRef {
                tool: "stripe.refunds.create".into(),
                args_hash: canonical::hash_json(&serde_json::json!({"amount": 4200})),
                result_hash: None,
                tool_hash: None,
            },
            GrantRef {
                provider: "stripe".into(),
                ttl_s: 30,
                single_use: true,
                status: "issued".into(),
            },
        )
    }

    fn sample_v2() -> GrantReceipt {
        let mut receipt = sample();
        receipt.v = 2;
        receipt.action_id = Some("action_1".into());
        receipt.principal = Some(PrincipalRef {
            principal_id: "user_1".into(),
            principal_type: "user".into(),
            authority_ref: "oauth_grant_1".into(),
            authority_hash: canonical::keccak256_str("authority"),
            verified_at: Some("2026-09-15T12:00:00Z".into()),
            verification_method: "oidc".into(),
        });
        receipt.agent_meta = Some(AgentRef {
            agent_id: receipt.agent.clone(),
            agent_version: Some("1.2.0".into()),
            model_id: Some("gpt-5".into()),
            operator_id: Some("acme".into()),
            environment: Some("prod".into()),
        });
        receipt.intent = Some(IntentRef {
            intent_hash: receipt.intent_hash.clone(),
            requested_scopes: vec!["refunds.create".into()],
            risk_class: Some("money-movement".into()),
            declared_purpose: Some("refund a duplicate charge".into()),
        });
        let policy_hash = canonical::keccak256_str("policy");
        receipt.authorization.policy_hash = Some(policy_hash.clone());
        receipt.policy = Some(PolicyRef {
            policy_id: "p1".into(),
            policy_version: 3,
            policy_hash,
            decision: "allow".into(),
            reason_code: Some("grant matched".into()),
            evaluated_inputs_hash: Some(canonical::keccak256_str("inputs")),
            evaluator_version: Some("tessera-policy-v1".into()),
        });
        receipt.credential = Some(CredentialRef {
            issuer: "stripe".into(),
            credential_type: "broker_grant".into(),
            thumbprint: canonical::keccak256_str("grant_1"),
            scopes: vec!["refunds.create".into()],
            ttl_seconds: 30,
            single_use: true,
            issuance_id: "grant_1".into(),
        });
        receipt.attestation = Some(AttestationRef {
            signer_key_id: "0x0000000000000000000000000000000000000000".into(),
            signature_alg: "secp256k1-eip712".into(),
            timestamp: Some(receipt.ts.clone()),
            transparency_log_index: None,
            anchor_ref: None,
        });
        receipt
    }

    #[tokio::test]
    async fn v2_sign_and_verify_roundtrip() {
        let signer = ReceiptSigner::from_hex_or_random(
            None,
            84532,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        let mut r = sample_v2();
        signer.sign(&mut r).await.unwrap();
        validate_v2(&r).unwrap();
        assert!(signer.verify(&r, &signer.address_hex()).unwrap());
    }

    #[test]
    fn v2_requires_the_binding_fields() {
        let mut r = sample_v2();
        r.principal = None;
        assert!(validate_v2(&r).is_err());
        let mut r = sample_v2();
        r.policy.as_mut().unwrap().policy_hash = "0x00".into();
        assert!(validate_v2(&r).is_err());
        let mut r = sample_v2();
        r.credential = None;
        assert!(validate_v2(&r).is_err());
        let mut r = sample_v2();
        r.authorization.decision = "deny".into();
        r.policy.as_mut().unwrap().decision = "deny".into();
        r.credential = None;
        validate_v2(&r).unwrap();
    }

    #[test]
    fn v2_uses_a_separate_domain_version() {
        let base = Domain::new(84532, "0x0000000000000000000000000000000000000000").unwrap();
        let v1 = sample();
        let v2 = sample_v2();
        let d1 = digest(&base, &v1).unwrap();
        let d2 = digest(&base, &v2).unwrap();
        assert_ne!(d1, d2);
    }

    #[tokio::test]
    async fn sign_and_verify_roundtrip() {
        let signer = ReceiptSigner::from_hex_or_random(
            None,
            84532,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        let mut r = sample();
        signer.sign(&mut r).await.unwrap();
        assert!(r.signature.is_some());
        assert!(signer.verify(&r, &signer.address_hex()).unwrap());
    }

    #[tokio::test]
    async fn tampering_invalidates_signature() {
        let signer = ReceiptSigner::from_hex_or_random(
            None,
            84532,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        let mut r = sample();
        signer.sign(&mut r).await.unwrap();
        r.call.args_hash = canonical::hash_json(&serde_json::json!({"amount": 999999}));
        assert!(!signer.verify(&r, &signer.address_hex()).unwrap());
    }

    #[test]
    fn deterministic_key_gives_stable_address() {
        let key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
        let a = ReceiptSigner::from_hex_or_random(
            Some(key),
            1,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        let b = ReceiptSigner::from_hex_or_random(
            Some(key),
            1,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(a.address_hex(), b.address_hex());
    }

    #[tokio::test]
    async fn payload_hash_ignores_signature() {
        let signer = ReceiptSigner::from_hex_or_random(
            None,
            1,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        let mut r = sample();
        let before = payload_hash_hex(&r).unwrap();
        signer.sign(&mut r).await.unwrap();
        let after = payload_hash_hex(&r).unwrap();
        assert_eq!(before, after);
    }
}
