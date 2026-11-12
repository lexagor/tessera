//! Signed audit export.
//!
//! An export is a self-contained bundle: the receipts of one agent chain plus a manifest
//! naming the tenant, count, chain head, a Merkle root over the exported receipts, and the
//! broker's signature over all of it. An auditor can verify the bundle offline with
//! [`verify_manifest`] + [`crate::receipt::verify`] + [`crate::merkle::verify`] — no broker
//! trust and no database access required.

use serde::{Deserialize, Serialize};

use crate::chain::ChainEntry;
use crate::error::BrokerError;

pub const EXPORT_VERSION: u32 = 1;
/// Upper bound on receipts in a single export (keeps responses and audits bounded).
pub const MAX_EXPORT_RECEIPTS: usize = 5_000;
/// Upper bound on agents in a tenant-wide export.
pub const MAX_EXPORT_AGENTS: usize = 100;
/// Append-only index of written archives (one signed JSON object per line).
pub const ARCHIVE_INDEX_FILE: &str = "INDEX.jsonl";

/// Static mapping from exported action records to the controls a reviewer, auditor, or
/// insurer commonly asks about. The mapping is an aid, not a certification.
pub fn controls_mapping() -> serde_json::Value {
    serde_json::json!({
        "disclaimer": "Mapping aid only; not a certification or legal opinion.",
        "recordFields": {
            "identity": ["agent", "agentMeta.agentId", "agentMeta.agentVersion", "agentMeta.modelId", "agentMeta.operatorId"],
            "authority": ["principal.principalId", "principal.authorityRef", "principal.authorityHash", "principal.verificationMethod"],
            "policy": ["authorization.policy", "authorization.policyVersion", "policy.policyHash", "policy.evaluatedInputsHash"],
            "action": ["call.tool", "call.toolHash", "call.argsHash", "call.nonce"],
            "credential": ["credential.issuer", "credential.credentialType", "credential.thumbprint", "credential.scopes", "credential.ttlSeconds", "credential.singleUse"],
            "outcome": ["outcome.status", "outcome.resultHash", "outcome.errorClass", "outcome.externalRef", "outcome.completedAt"],
            "integrity": ["prev", "signature", "attestation.signerKeyId"]
        },
        "frameworks": [
            {"id": "SOC2-CC6", "name": "SOC 2 logical access", "records": ["principal", "authorization", "credential"]},
            {"id": "SOC2-CC7", "name": "SOC 2 monitoring", "records": ["outcome", "prev", "signature"]},
            {"id": "ISO42001", "name": "AI management system operation", "records": ["agentMeta", "policy", "outcome"]},
            {"id": "EU-AI-ACT-12", "name": "Record-keeping", "records": ["call", "outcome", "attestation"]},
            {"id": "EU-AI-ACT-26", "name": "Deployer human oversight", "records": ["principal", "policy"]},
            {"id": "FINRA", "name": "Supervision of agent actions", "records": ["authorization", "outcome"]},
            {"id": "SEC-17A-4", "name": "WORM retention", "records": ["prev", "signature", "manifest"]},
            {"id": "DORA-17", "name": "ICT incident logging", "records": ["outcome.status", "outcome.errorClass"]}
        ]
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub version: u32,
    pub tenant: String,
    pub agent: String,
    /// RFC 3339 timestamp of the export.
    pub exported_at: String,
    /// Number of receipts in this bundle.
    pub receipt_count: u64,
    /// Total chain length at export time (may exceed `receipt_count` if truncated).
    pub chain_length: u64,
    /// Payload hash of the newest receipt in the bundle.
    pub head: Option<String>,
    /// Merkle root over the exported receipts' leaves.
    pub merkle_root: String,
    /// Broker signer address.
    pub signer: String,
    /// Broker signature over [`manifest_digest`]; filled last.
    pub signature: String,
    /// Address of the tenant's own signing key, when one is configured. Lets an auditor
    /// anchor trust in the tenant rather than (only) the broker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_signer: Option<String>,
    /// Tenant signature over the same digest, when a tenant key is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_signature: Option<String>,
    /// True when the chain was longer than [`MAX_EXPORT_RECEIPTS`].
    #[serde(default)]
    pub truncated: bool,
    /// Chain index of the first receipt in this bundle (0 = starts at genesis).
    #[serde(default)]
    pub from_index: u64,
    /// Payload hash of the receipt *before* `from_index`, when the bundle is a page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_before: Option<String>,
    /// Index of the next page, when more receipts exist beyond this bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_from: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub manifest: ExportManifest,
    pub receipts: Vec<ChainEntry>,
}

/// Tenant-wide export: one signed sub-bundle per agent plus an aggregate manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantExportBundle {
    pub manifest: TenantExportManifest,
    pub agents: Vec<ExportBundle>,
    /// Anchor records (Merkle roots submitted on-chain) covering the exported agents.
    #[serde(default)]
    pub anchors: Vec<serde_json::Value>,
    /// The tenant's key-event ledger (hash-linked), when included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_events: Vec<crate::key_events::KeyEvent>,
    /// Chain checkpoints taken when the archives were written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoints: Vec<crate::chain_checkpoints::ChainCheckpoint>,
    /// Policy versions referenced by the exported receipts (content hash + document).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<crate::policy::PolicyVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantExportManifest {
    pub version: u32,
    pub tenant: String,
    pub exported_at: String,
    pub agent_count: u64,
    pub receipt_count: u64,
    /// Combined Merkle root over every exported receipt leaf, agent by agent.
    pub merkle_root: String,
    /// Per-agent head hashes, sorted by agent id.
    pub agent_heads: Vec<(String, Option<String>)>,
    pub signer: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_signature: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    /// Digest of the included key-event ledger (covered by the signature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_events_digest: Option<String>,
    /// Digest of the included checkpoints (covered by the signature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoints_digest: Option<String>,
    /// Digest of the included policy versions (covered by the signature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies_digest: Option<String>,
}

impl TenantExportBundle {
    /// Verify every agent sub-bundle and the aggregate manifest over them.
    pub fn verify(&self) -> Result<bool, BrokerError> {
        if self.agents.len() as u64 != self.manifest.agent_count {
            return Ok(false);
        }
        let mut total = 0u64;
        let mut leaves = Vec::new();
        let mut heads = Vec::new();
        let mut truncated = false;

        let mut sorted: Vec<&ExportBundle> = self.agents.iter().collect();
        sorted.sort_by(|a, b| a.manifest.agent.cmp(&b.manifest.agent));

        for bundle in sorted {
            if !bundle.verify()? {
                return Ok(false);
            }
            if bundle.manifest.tenant != self.manifest.tenant {
                return Ok(false);
            }
            total += bundle.manifest.receipt_count;
            truncated |= bundle.manifest.truncated;
            heads.push((bundle.manifest.agent.clone(), bundle.manifest.head.clone()));
            for entry in &bundle.receipts {
                leaves.push(crate::merkle::leaf_for_receipt(&entry.receipt)?);
            }
        }

        if total != self.manifest.receipt_count || truncated != self.manifest.truncated {
            return Ok(false);
        }
        if heads != self.manifest.agent_heads {
            return Ok(false);
        }
        // Key-event ledger: hash linkage, then the manifest digest binding.
        if let Some(expected) = &self.manifest.key_events_digest {
            if !crate::key_events::verify_chain(&self.key_events) {
                return Ok(false);
            }
            if digest_of(&self.key_events)? != *expected {
                return Ok(false);
            }
        }
        // Checkpoints: exact match against the manifest digest.
        if let Some(expected) = &self.manifest.checkpoints_digest {
            if digest_of(&self.checkpoints)? != *expected {
                return Ok(false);
            }
        }
        // Policy snapshots: each document must hash to its recorded content hash, and the
        // whole set must match the signed manifest digest.
        if !self.policies.is_empty() && self.manifest.policies_digest.is_none() {
            return Ok(false);
        }
        if let Some(expected) = &self.manifest.policies_digest {
            for policy in &self.policies {
                if crate::canonical::hash_json(&policy.document) != policy.content_hash {
                    return Ok(false);
                }
            }
            if digest_of(&self.policies)? != *expected {
                return Ok(false);
            }
        }
        let root = crate::merkle::MerkleTree::new(leaves).root();
        if self.manifest.merkle_root != format!("0x{}", hex::encode(root)) {
            return Ok(false);
        }

        // Aggregate signature over the tenant manifest.
        let digest = tenant_manifest_digest(&self.manifest)?;
        let recovered = crate::receipt::recover_hash(&digest, &self.manifest.signature)?;
        if !recovered.eq_ignore_ascii_case(&self.manifest.signer) {
            return Ok(false);
        }
        match (
            &self.manifest.tenant_signer,
            &self.manifest.tenant_signature,
        ) {
            (None, None) => Ok(true),
            (Some(expected), Some(signature)) => {
                let recovered = crate::receipt::recover_hash(&digest, signature)?;
                Ok(recovered.eq_ignore_ascii_case(expected))
            }
            _ => Ok(false),
        }
    }
}

/// Build a single-file auditor archive (tar.gz): README, manifest, per-agent bundles, anchors.
pub fn build_tenant_archive(
    bundle: &TenantExportBundle,
    verify_command_hint: &str,
) -> Result<Vec<u8>, BrokerError> {
    let mut tar_bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let readme = format!(
            "Tessera audit export\n\
             ====================\n\n\
             tenant:        {tenant}\n\
             exported at:   {exported_at}\n\
             agents:        {agents}\n\
             receipts:      {receipts}\n\
             combined root: {root}\n\
             broker signer: {broker}\n\
             tenant signer: {tenant_signer}\n\n\
             Contents\n\
             --------\n\
             manifest.json      aggregate manifest (agent count, heads, combined Merkle root)\n\
             agents/<id>.json   per-agent bundle: signed manifest + receipts\n\
             anchors.json       on-chain anchor records for this tenant\n\
             key-events.json    hash-linked key lifecycle ledger (create/renew/revoke)\n\
             checkpoints.json   chain heads/counts as of each archive\n\
             policies.json      policy versions referenced by the receipts\n\
             controls.json      records-to-controls mapping (SOC 2, ISO 42001, EU AI Act, FINRA, SEC, DORA)\n\n\
             How to verify\n\
             -------------\n\
             1. Untar this archive and verify the whole thing offline with the tessera-verify CLI:\n\
                {cmd}\n\
             2. Or verify each agent bundle individually (each is self-contained):\n\
                {cmd_agents}\n\
             Both checks cover: receipt linkage (prev -> payload hash), the Merkle root over\n\
             every exported receipt, and the broker (and optional tenant) signatures.\n\
             No broker, database, or network access is required.\n\n\
             Domain tags\n\
             -----------\n\
             export manifests: tessera-export-v1\n\
             EIP-712 receipts:  TesseraReceipt v1/v2 (chain id + verifying contract)\n",
            tenant = bundle.manifest.tenant,
            exported_at = bundle.manifest.exported_at,
            agents = bundle.manifest.agent_count,
            receipts = bundle.manifest.receipt_count,
            root = bundle.manifest.merkle_root,
            broker = bundle.manifest.signer,
            tenant_signer = bundle.manifest.tenant_signer.as_deref().unwrap_or("(none)"),
            cmd = verify_command_hint,
            cmd_agents = "tessera-verify agents/<agent>.json (repeat per agent)",
        );

        let mut add = |name: &str, bytes: Vec<u8>| -> Result<(), BrokerError> {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, bytes.as_slice())
                .map_err(|e| BrokerError::Internal(format!("archive entry {name}: {e}")))?;
            Ok(())
        };

        add("README.txt", readme.into_bytes())?;
        add(
            "manifest.json",
            serde_json::to_vec_pretty(&bundle.manifest)
                .map_err(|e| BrokerError::Internal(format!("serialize manifest: {e}")))?,
        )?;
        add(
            "anchors.json",
            serde_json::to_vec_pretty(&bundle.anchors)
                .map_err(|e| BrokerError::Internal(format!("serialize anchors: {e}")))?,
        )?;
        add(
            "key-events.json",
            serde_json::to_vec_pretty(&bundle.key_events)
                .map_err(|e| BrokerError::Internal(format!("serialize key events: {e}")))?,
        )?;
        add(
            "checkpoints.json",
            serde_json::to_vec_pretty(&bundle.checkpoints)
                .map_err(|e| BrokerError::Internal(format!("serialize checkpoints: {e}")))?,
        )?;
        add(
            "controls.json",
            serde_json::to_vec_pretty(&controls_mapping())
                .map_err(|e| BrokerError::Internal(format!("serialize controls: {e}")))?,
        )?;
        add(
            "policies.json",
            serde_json::to_vec_pretty(&bundle.policies)
                .map_err(|e| BrokerError::Internal(format!("serialize policies: {e}")))?,
        )?;
        for agent in &bundle.agents {
            // Agent ids are client-supplied: never let them escape the archive directory.
            let name = format!(
                "agents/{}.json",
                crate::auth::safe_agent_filename(&agent.manifest.agent)
            );
            add(
                &name,
                serde_json::to_vec_pretty(agent)
                    .map_err(|e| BrokerError::Internal(format!("serialize agent: {e}")))?,
            )?;
        }

        let encoder = builder
            .into_inner()
            .map_err(|e| BrokerError::Internal(format!("archive finish: {e}")))?;
        encoder
            .finish()
            .map_err(|e| BrokerError::Internal(format!("gzip finish: {e}")))?;
    }
    Ok(tar_bytes)
}

/// Digest of an arbitrary serializable value, for manifest bindings.
pub fn digest_of<T: serde::Serialize>(value: &T) -> Result<String, BrokerError> {
    let value = serde_json::to_value(value)
        .map_err(|e| BrokerError::Internal(format!("serialize for digest: {e}")))?;
    Ok(crate::canonical::hash_json(&value))
}

/// Digest for a tenant manifest (same domain tag as single-agent exports).
pub fn tenant_manifest_digest(manifest: &TenantExportManifest) -> Result<[u8; 32], BrokerError> {
    let mut value = serde_json::to_value(manifest)
        .map_err(|e| BrokerError::Internal(format!("serialize manifest: {e}")))?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
        object.remove("tenant_signature");
    }
    payload_digest("tessera-export-v1", &value)
}

impl ExportBundle {
    /// Verify the manifest signature and every receipt's linkage + signature digest.
    /// Returns the recovered signer address when the bundle is internally consistent.
    pub fn verify(&self) -> Result<bool, BrokerError> {
        if self.receipts.len() as u64 != self.manifest.receipt_count {
            return Ok(false);
        }
        // An empty page (from >= chain length) has no head but still names its predecessor.
        if self.receipts.is_empty() {
            let shape_ok = match (self.manifest.from_index, &self.manifest.prev_before) {
                (0, None) => true,
                (from, Some(_)) if from > 0 => true,
                _ => false,
            };
            return Ok(shape_ok && self.manifest.head.is_none());
        }
        // Linkage: each receipt's `prev` must match the previous receipt's payload hash. A
        // page (from_index > 0) instead starts at the recorded predecessor hash.
        let mut prev: Option<String> = self.manifest.prev_before.clone();
        if self.manifest.from_index == 0 && self.manifest.prev_before.is_some() {
            return Ok(false);
        }
        if self.manifest.from_index > 0
            && self.manifest.prev_before.is_none()
            && !self.receipts.is_empty()
        {
            return Ok(false);
        }
        for entry in &self.receipts {
            if crate::receipt::validate_v2(&entry.receipt).is_err() {
                return Ok(false);
            }
            if entry.receipt.prev != prev {
                return Ok(false);
            }
            prev = Some(entry.payload_hash.clone());
        }
        if self.manifest.head != prev {
            return Ok(false);
        }
        // A continuation pointer, when present, must move forward (no loops).
        if let Some(next) = self.manifest.next_from {
            if next <= self.manifest.from_index {
                return Ok(false);
            }
        }
        // Merkle root over the receipt leaves.
        let mut leaves = Vec::with_capacity(self.receipts.len());
        for entry in &self.receipts {
            leaves.push(crate::merkle::leaf_for_receipt(&entry.receipt)?);
        }
        let root = crate::merkle::MerkleTree::new(leaves).root();
        if self.manifest.merkle_root != format!("0x{}", hex::encode(root)) {
            return Ok(false);
        }
        if !verify_manifest(&self.manifest)? {
            return Ok(false);
        }
        // A tenant signature, when claimed, must verify against the claimed address.
        match (
            &self.manifest.tenant_signer,
            &self.manifest.tenant_signature,
        ) {
            (None, None) => Ok(true),
            (Some(expected), Some(signature)) => {
                let digest = manifest_digest(&self.manifest)?;
                let recovered = crate::receipt::recover_hash(&digest, signature)?;
                Ok(recovered.eq_ignore_ascii_case(expected))
            }
            // A claimed signer without a signature (or vice versa) is malformed.
            _ => Ok(false),
        }
    }
}

/// Domain tag mixed into the manifest digest so an export signature can never be replayed
/// as (or mistaken for) any other Tessera signature.
const MANIFEST_DOMAIN: &[u8] = b"tessera-export-v1";
/// Domain tag for signed posture snapshots (`GET /v1/limits?sign=true`).
pub const LIMITS_DOMAIN: &str = "tessera-limits-v1";
/// Domain tag for archive-index entries (`INDEX.jsonl` next to written archives).
pub const ARCHIVE_INDEX_DOMAIN: &str = "tessera-archive-index-v1";
/// Domain tag for anchor-gap alert webhooks.
pub const ALERT_DOMAIN: &str = "tessera-alert-v1";
/// Domain tag for signed integrity snapshots.
pub const INTEGRITY_DOMAIN: &str = "tessera-integrity-v1";
/// Domain tag for restore attestations.
pub const RESTORE_DOMAIN: &str = "tessera-restore-v1";

/// A payload signed by the broker (domain-tagged, offline-verifiable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPayload {
    /// Domain tag the digest was bound to.
    pub domain: String,
    /// Keccak-256 digest that was signed.
    pub digest: String,
    /// Signer address.
    pub signer: String,
    /// 65-byte secp256k1 signature over the digest.
    pub signature: String,
    /// RFC 3339 timestamp.
    pub signed_at: String,
}

/// Domain-tagged digest of an arbitrary JSON payload: `keccak(domain ‖ canonical json)`.
pub fn payload_digest(domain: &str, payload: &serde_json::Value) -> Result<[u8; 32], BrokerError> {
    let canonical = crate::canonical::canonicalize(payload);
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.extend_from_slice(canonical.as_bytes());
    Ok(crate::merkle::keccak(&preimage))
}

/// Sign an arbitrary JSON payload with the broker key.
pub async fn sign_payload(
    signer: &crate::receipt::ReceiptSigner,
    domain: &str,
    payload: &serde_json::Value,
) -> Result<SignedPayload, BrokerError> {
    let digest = payload_digest(domain, payload)?;
    let signature = signer.sign_hash(&digest).await?;
    Ok(SignedPayload {
        domain: domain.to_string(),
        digest: format!("0x{}", hex::encode(digest)),
        signer: signer.address_hex(),
        signature,
        signed_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Verify a signed payload offline. `accept_signers` may be empty to accept any signer
/// (the recovered address is still returned by the caller for inspection).
pub fn verify_signed_payload(
    domain: &str,
    payload: &serde_json::Value,
    signed: &SignedPayload,
    accept_signers: &[String],
) -> Result<bool, BrokerError> {
    if signed.domain != domain {
        return Ok(false);
    }
    let digest = payload_digest(domain, payload)?;
    if signed.digest != format!("0x{}", hex::encode(digest)) {
        return Ok(false);
    }
    let recovered = crate::receipt::recover_hash(&digest, &signed.signature)?;
    if !recovered.eq_ignore_ascii_case(&signed.signer) {
        return Ok(false);
    }
    if accept_signers.is_empty() {
        return Ok(true);
    }
    Ok(accept_signers
        .iter()
        .any(|expected| recovered.eq_ignore_ascii_case(expected)))
}

/// Digest bound by the manifest signatures: Keccak-256 over a domain tag followed by the
/// canonical JSON of every manifest field except the two signature fields.
pub fn manifest_digest(manifest: &ExportManifest) -> Result<[u8; 32], BrokerError> {
    let mut value = serde_json::to_value(manifest)
        .map_err(|e| BrokerError::Internal(format!("serialize manifest: {e}")))?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
        object.remove("tenant_signature");
    }
    let canonical = crate::canonical::canonicalize(&value);
    let mut preimage = Vec::with_capacity(MANIFEST_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(MANIFEST_DOMAIN);
    preimage.extend_from_slice(canonical.as_bytes());
    Ok(crate::merkle::keccak(&preimage))
}

/// Verify a manifest's signature offline (no broker trust).
pub fn verify_manifest(manifest: &ExportManifest) -> Result<bool, BrokerError> {
    let digest = manifest_digest(manifest)?;
    let recovered = crate::receipt::recover_hash(&digest, &manifest.signature)?;
    Ok(recovered.eq_ignore_ascii_case(&manifest.signer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{GrantReceipt, ReceiptSigner};

    const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    fn manifest() -> ExportManifest {
        ExportManifest {
            version: EXPORT_VERSION,
            tenant: "acme".into(),
            agent: "billing".into(),
            exported_at: "2026-09-17T00:00:00Z".into(),
            receipt_count: 0,
            chain_length: 0,
            head: None,
            merkle_root: format!("0x{}", hex::encode([0u8; 32])),
            signer: "0x0000000000000000000000000000000000000000".into(),
            signature: "0x".into(),
            tenant_signer: None,
            tenant_signature: None,
            truncated: false,
            from_index: 0,
            prev_before: None,
            next_from: None,
        }
    }

    #[tokio::test]
    async fn manifest_signature_round_trips_and_detects_tampering() {
        let signer = ReceiptSigner::from_hex_or_random(
            Some(TEST_KEY),
            84532,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap();
        let mut m = manifest();
        m.signer = signer.address_hex();
        let digest = manifest_digest(&m).unwrap();
        m.signature = signer.sign_hash(&digest).await.unwrap();
        assert!(verify_manifest(&m).unwrap());

        // Tampering with any covered field invalidates the signature.
        let mut tampered = m.clone();
        tampered.receipt_count = 1;
        assert!(!verify_manifest(&tampered).unwrap());

        let mut tampered = m.clone();
        tampered.agent = "other".into();
        assert!(!verify_manifest(&tampered).unwrap());
    }

    #[test]
    fn receipt_without_signature_still_has_a_leaf() {
        let receipt = GrantReceipt {
            v: 1,
            tenant: "acme".into(),
            agent: "a".into(),
            user: "u".into(),
            intent_hash: "0x00".into(),
            authorization: crate::receipt::AuthorizationRef {
                decision: "allow".into(),
                policy: "p".into(),
                policy_version: 1,
                resource: "stripe:refunds.create".into(),
                anomaly_score: 0.0,
                policy_hash: None,
            },
            call: crate::receipt::CallRef {
                tool: "stripe.refunds.create".into(),
                args_hash: "0x00".into(),
                result_hash: None,
                tool_hash: None,
            },
            grant: crate::receipt::GrantRef {
                provider: "stripe".into(),
                ttl_s: 30,
                single_use: true,
                status: "issued".into(),
            },
            ts: "2026-09-17T00:00:00Z".into(),
            nonce: "0x00".into(),
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
        };
        assert!(crate::merkle::leaf_for_receipt(&receipt).is_ok());
    }
}
