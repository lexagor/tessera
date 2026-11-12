//! Anchor records and per-tenant anchor targets (multi-chain).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRecord {
    pub id: String,
    pub tenant: String,
    pub agent: String,
    pub merkle_root: String,
    pub count: u64,
    pub chain_id: u64,
    pub contract: String,
    /// The submitted transaction hash; `None` while a claim is in flight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    pub status: String,
    /// Block the tx was mined in (set once confirmed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    pub created_at: String,
}

/// Where a tenant's anchors are submitted (per-tenant chain/contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorTarget {
    pub chain_id: u64,
    pub rpc_url: String,
    pub contract: String,
    /// Optional tenant-specific signing key; falls back to the broker's `ANCHOR_PK`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Addresses of previously configured tenant keys (for verifying older co-signed
    /// artifacts). Maintained by the broker on rotation; supplied values are ignored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signer_history: Vec<String>,
}

#[async_trait]
pub trait AnchorStore: Send + Sync {
    async fn record(&self, record: AnchorRecord) -> Result<(), BrokerError>;
    async fn list(&self, tenant: &str) -> Result<Vec<AnchorRecord>, BrokerError>;
    async fn latest(&self, tenant: &str, agent: &str) -> Result<Option<AnchorRecord>, BrokerError>;
    /// Anchors that are not yet `finalized` (candidates for reconfirmation).
    ///
    /// Status lifecycle: `submitted` -> `confirmed` -> `finalized`, with `failed` for a
    /// reverted tx and `reorged` for a tx that vanished from the canonical chain.
    async fn pending(&self, tenant: &str) -> Result<Vec<AnchorRecord>, BrokerError>;
    /// Reserve the right to submit an anchor for this root. Returns `AlreadyClaimed` when a
    /// live record already covers it (another replica or an in-flight submission).
    async fn claim(
        &self,
        tenant: &str,
        agent: &str,
        merkle_root: &str,
        count: u64,
        chain_id: u64,
        contract: &str,
    ) -> Result<ClaimOutcome, BrokerError>;

    /// Delete terminal (finalized/failed/reorged) anchor records older than `cutoff`.
    async fn prune_before(
        &self,
        _cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        Ok(0)
    }

    /// Attach the submitted tx hash / status to a claimed record (tenant-scoped).
    async fn settle(
        &self,
        tenant: &str,
        id: &str,
        tx_hash: &str,
        status: &str,
        block_number: Option<u64>,
    ) -> Result<(), BrokerError>;

    /// Update an anchor's status / mined block (tenant-scoped).
    async fn update(
        &self,
        tenant: &str,
        id: &str,
        status: &str,
        block_number: Option<u64>,
    ) -> Result<(), BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[async_trait]
pub trait AnchorTargetStore: Send + Sync {
    async fn set(&self, tenant: &str, target: AnchorTarget) -> Result<(), BrokerError>;
    async fn get(&self, tenant: &str) -> Result<Option<AnchorTarget>, BrokerError>;
    async fn list(&self) -> Result<Vec<(String, AnchorTarget)>, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

pub fn new_record(
    tenant: &str,
    agent: &str,
    merkle_root: &str,
    count: u64,
    chain_id: u64,
    contract: &str,
    tx_hash: &str,
) -> AnchorRecord {
    AnchorRecord {
        id: format!("anc_{}", uuid::Uuid::new_v4().simple()),
        tenant: tenant.to_string(),
        agent: agent.to_string(),
        merkle_root: merkle_root.to_string(),
        count,
        chain_id,
        contract: contract.to_string(),
        tx_hash: Some(tx_hash.to_string()),
        status: "submitted".to_string(),
        block_number: None,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// A claim: a reservation to submit an anchor for `(tenant, agent, merkle_root)`.
pub fn new_claim(
    tenant: &str,
    agent: &str,
    merkle_root: &str,
    count: u64,
    chain_id: u64,
    contract: &str,
) -> AnchorRecord {
    let mut record = new_record(tenant, agent, merkle_root, count, chain_id, contract, "");
    record.tx_hash = None;
    record.status = "claimed".to_string();
    record
}

/// Result of attempting to claim an anchor submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed {
        id: String,
    },
    /// Another (live) record already covers this root.
    AlreadyClaimed,
}

/// Statuses that still "hold" a root against re-claiming.
fn holds_root(status: &str) -> bool {
    !matches!(status, "failed" | "reorged")
}

#[derive(Default)]
pub struct MemoryAnchorStore {
    records: Mutex<Vec<AnchorRecord>>,
}

impl MemoryAnchorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AnchorStore for MemoryAnchorStore {
    async fn record(&self, record: AnchorRecord) -> Result<(), BrokerError> {
        self.records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?
            .push(record);
        Ok(())
    }

    async fn prune_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        let before = records.len();
        records.retain(|r| {
            let terminal = matches!(r.status.as_str(), "finalized" | "failed" | "reorged");
            let old = chrono::DateTime::parse_from_rfc3339(&r.created_at)
                .map(|t| t.with_timezone(&chrono::Utc) < cutoff)
                .unwrap_or(false);
            !(terminal && old)
        });
        Ok((before - records.len()) as u64)
    }

    async fn claim(
        &self,
        tenant: &str,
        agent: &str,
        merkle_root: &str,
        count: u64,
        chain_id: u64,
        contract: &str,
    ) -> Result<ClaimOutcome, BrokerError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        if records.iter().any(|r| {
            r.tenant == tenant
                && r.agent == agent
                && r.merkle_root == merkle_root
                && holds_root(&r.status)
        }) {
            return Ok(ClaimOutcome::AlreadyClaimed);
        }
        let record = new_claim(tenant, agent, merkle_root, count, chain_id, contract);
        let id = record.id.clone();
        records.push(record);
        Ok(ClaimOutcome::Claimed { id })
    }

    async fn settle(
        &self,
        tenant: &str,
        id: &str,
        tx_hash: &str,
        status: &str,
        block_number: Option<u64>,
    ) -> Result<(), BrokerError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        if let Some(record) = records
            .iter_mut()
            .find(|r| r.id == id && r.tenant == tenant)
        {
            record.tx_hash = Some(tx_hash.to_string());
            record.status = status.to_string();
            record.block_number = block_number;
        }
        Ok(())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<AnchorRecord>, BrokerError> {
        let records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        Ok(records
            .iter()
            .filter(|r| r.tenant == tenant)
            .cloned()
            .collect())
    }

    async fn latest(&self, tenant: &str, agent: &str) -> Result<Option<AnchorRecord>, BrokerError> {
        let records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        Ok(records
            .iter()
            .rfind(|r| r.tenant == tenant && r.agent == agent)
            .cloned())
    }

    async fn pending(&self, tenant: &str) -> Result<Vec<AnchorRecord>, BrokerError> {
        let records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        Ok(records
            .iter()
            .filter(|r| r.tenant == tenant && r.status != "finalized")
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        tenant: &str,
        id: &str,
        status: &str,
        block_number: Option<u64>,
    ) -> Result<(), BrokerError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| BrokerError::Internal("anchor store poisoned".into()))?;
        if let Some(record) = records
            .iter_mut()
            .find(|r| r.id == id && r.tenant == tenant)
        {
            record.status = status.to_string();
            record.block_number = block_number;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryAnchorTargetStore {
    targets: Mutex<HashMap<String, AnchorTarget>>,
}

impl MemoryAnchorTargetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AnchorTargetStore for MemoryAnchorTargetStore {
    async fn set(&self, tenant: &str, target: AnchorTarget) -> Result<(), BrokerError> {
        self.targets
            .lock()
            .map_err(|_| BrokerError::Internal("anchor target store poisoned".into()))?
            .insert(tenant.to_string(), target);
        Ok(())
    }

    async fn get(&self, tenant: &str) -> Result<Option<AnchorTarget>, BrokerError> {
        Ok(self
            .targets
            .lock()
            .map_err(|_| BrokerError::Internal("anchor target store poisoned".into()))?
            .get(tenant)
            .cloned())
    }

    async fn list(&self) -> Result<Vec<(String, AnchorTarget)>, BrokerError> {
        Ok(self
            .targets
            .lock()
            .map_err(|_| BrokerError::Internal("anchor target store poisoned".into()))?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

/// Decision for one pending anchor during a reconfirmation sweep.
fn age_secs(record: &AnchorRecord, now: chrono::DateTime<chrono::Utc>) -> u64 {
    chrono::DateTime::parse_from_rfc3339(&record.created_at)
        .map(|t| (now - t.with_timezone(&chrono::Utc)).num_seconds().max(0) as u64)
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconfirmAction {
    /// Leave the record as-is (still pending, nothing new).
    Keep,
    /// Record observed status / block number.
    Update {
        status: String,
        block_number: Option<u64>,
    },
    /// The transaction is gone: the record should be marked `reorged` and re-anchored.
    Reanchor,
}

/// Pure decision function for anchor reconfirmation (unit-testable without a chain).
///
/// - a reverted tx becomes `failed`;
/// - a mined tx becomes `finalized` once `confirmations` blocks are on top of it, else
///   `confirmed`;
/// - a tx that is neither mined nor reverted beyond `grace_secs` is assumed reorged out and
///   should be re-anchored (only while the record still looks live).
pub fn plan_reconfirmation(
    record: &AnchorRecord,
    observation: Option<(bool, u64)>,
    head_block: u64,
    confirmations: u64,
    now: chrono::DateTime<chrono::Utc>,
    grace_secs: u64,
) -> ReconfirmAction {
    // An unsettled claim (no tx yet) is left to the submitting replica; if it goes stale the
    // claim is abandoned and re-anchored.
    if record.tx_hash.is_none() {
        let age = age_secs(record, now);
        return if age > grace_secs {
            ReconfirmAction::Reanchor
        } else {
            ReconfirmAction::Keep
        };
    }
    match observation {
        Some((false, block)) => ReconfirmAction::Update {
            status: "failed".to_string(),
            block_number: Some(block),
        },
        Some((true, block)) => {
            if head_block >= block.saturating_add(confirmations) {
                ReconfirmAction::Update {
                    status: "finalized".to_string(),
                    block_number: Some(block),
                }
            } else {
                ReconfirmAction::Update {
                    status: "confirmed".to_string(),
                    block_number: Some(block),
                }
            }
        }
        None => {
            let age = age_secs(record, now);
            let live = matches!(record.status.as_str(), "submitted" | "confirmed");
            if live && age > grace_secs {
                ReconfirmAction::Reanchor
            } else {
                ReconfirmAction::Keep
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn updates_status_and_block() {
        let store = MemoryAnchorStore::new();
        let record = new_record("acme", "a1", "0xroot", 3, 84532, "0xc", "0xtx");
        let id = record.id.clone();
        store.record(record).await.unwrap();

        assert_eq!(store.pending("acme").await.unwrap().len(), 1);
        store
            .update("acme", &id, "confirmed", Some(42))
            .await
            .unwrap();

        let latest = store.latest("acme", "a1").await.unwrap().unwrap();
        assert_eq!(latest.status, "confirmed");
        assert_eq!(latest.block_number, Some(42));
        // "confirmed" is still pending finality
        assert_eq!(store.pending("acme").await.unwrap().len(), 1);

        store
            .update("acme", &id, "finalized", Some(42))
            .await
            .unwrap();
        assert!(store.pending("acme").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn claim_prevents_duplicate_submissions() {
        let store = MemoryAnchorStore::new();
        let first = store
            .claim("acme", "a1", "0xroot", 3, 1, "0xc")
            .await
            .unwrap();
        assert!(matches!(first, ClaimOutcome::Claimed { .. }));

        // second claim for the same root is refused
        assert_eq!(
            store
                .claim("acme", "a1", "0xroot", 3, 1, "0xc")
                .await
                .unwrap(),
            ClaimOutcome::AlreadyClaimed
        );
        // a different root/agent is fine
        assert!(matches!(
            store
                .claim("acme", "a1", "0xother", 3, 1, "0xc")
                .await
                .unwrap(),
            ClaimOutcome::Claimed { .. }
        ));

        // once settled, the root is still held
        let id = match first {
            ClaimOutcome::Claimed { id } => id,
            _ => unreachable!(),
        };
        store
            .settle("acme", &id, "0xtx", "confirmed", Some(9))
            .await
            .unwrap();
        assert_eq!(
            store
                .claim("acme", "a1", "0xroot", 3, 1, "0xc")
                .await
                .unwrap(),
            ClaimOutcome::AlreadyClaimed
        );
    }

    #[tokio::test]
    async fn prune_removes_only_terminal_old_records() {
        let store = MemoryAnchorStore::new();
        // live claim (not terminal) + a finalized record, both "old"
        let ClaimOutcome::Claimed { .. } = store
            .claim("acme", "a1", "0xr1", 1, 1, "0xc")
            .await
            .unwrap()
        else {
            panic!("claim");
        };
        let settled = new_record("acme", "a2", "0xr2", 1, 1, "0xc", "0xtx");
        let id = settled.id.clone();
        store.record(settled).await.unwrap();
        store
            .settle("acme", &id, "0xtx", "finalized", Some(1))
            .await
            .unwrap();

        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        // only the finalized record is pruned; the live claim is kept
        assert_eq!(store.prune_before(future).await.unwrap(), 1);
        assert_eq!(AnchorStore::list(&store, "acme").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stale_claim_is_reanchored() {
        let store = MemoryAnchorStore::new();
        let ClaimOutcome::Claimed { id } = store
            .claim("acme", "a1", "0xroot", 3, 1, "0xc")
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };
        let record = store.latest("acme", "a1").await.unwrap().unwrap();
        assert!(record.tx_hash.is_none());
        let now = chrono::Utc::now();
        // fresh claim: keep
        assert_eq!(
            plan_reconfirmation(&record, None, 1, 12, now, 300),
            ReconfirmAction::Keep
        );
        // stale claim: re-anchor
        assert_eq!(
            plan_reconfirmation(
                &record,
                None,
                1,
                12,
                now + chrono::Duration::seconds(600),
                300
            ),
            ReconfirmAction::Reanchor
        );
        // abandoning the claim allows a re-claim
        store.update("acme", &id, "reorged", None).await.unwrap();
        assert!(matches!(
            store
                .claim("acme", "a1", "0xroot", 3, 1, "0xc")
                .await
                .unwrap(),
            ClaimOutcome::Claimed { .. }
        ));
    }

    #[test]
    fn reconfirmation_planner() {
        let mut record = new_record("acme", "a1", "0xroot", 1, 1, "0xc", "0xtx");
        let now = chrono::Utc::now();

        // newly submitted, still pending -> keep
        assert_eq!(
            plan_reconfirmation(&record, None, 100, 12, now, 300),
            ReconfirmAction::Keep
        );

        // mined but shallow -> confirmed
        assert_eq!(
            plan_reconfirmation(&record, Some((true, 100)), 105, 12, now, 300),
            ReconfirmAction::Update {
                status: "confirmed".into(),
                block_number: Some(100)
            }
        );

        // enough depth -> finalized
        assert_eq!(
            plan_reconfirmation(&record, Some((true, 100)), 112, 12, now, 300),
            ReconfirmAction::Update {
                status: "finalized".into(),
                block_number: Some(100)
            }
        );

        // reverted -> failed
        assert_eq!(
            plan_reconfirmation(&record, Some((false, 100)), 112, 12, now, 300),
            ReconfirmAction::Update {
                status: "failed".into(),
                block_number: Some(100)
            }
        );

        // vanished long ago while still live -> re-anchor
        record.created_at = (now - chrono::Duration::seconds(600))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert_eq!(
            plan_reconfirmation(&record, None, 200, 12, now, 300),
            ReconfirmAction::Reanchor
        );

        // already marked reorged -> don't loop
        record.status = "reorged".into();
        assert_eq!(
            plan_reconfirmation(&record, None, 200, 12, now, 300),
            ReconfirmAction::Keep
        );
    }

    #[tokio::test]
    async fn records_and_targets() {
        let store = MemoryAnchorStore::new();
        store
            .record(new_record(
                "acme",
                "a1",
                "0xroot",
                3,
                84532,
                "0xcontract",
                "0xtx",
            ))
            .await
            .unwrap();
        assert_eq!(store.list("acme").await.unwrap().len(), 1);
        assert_eq!(
            store
                .latest("acme", "a1")
                .await
                .unwrap()
                .unwrap()
                .merkle_root,
            "0xroot"
        );
        assert!(store.latest("acme", "other").await.unwrap().is_none());

        let targets = MemoryAnchorTargetStore::new();
        targets
            .set(
                "acme",
                AnchorTarget {
                    chain_id: 8453,
                    rpc_url: "https://mainnet.base.org".into(),
                    contract: "0xabc".into(),
                    private_key: None,
                    signer_history: vec![],
                },
            )
            .await
            .unwrap();
        assert_eq!(targets.get("acme").await.unwrap().unwrap().chain_id, 8453);
        assert!(targets.get("other").await.unwrap().is_none());
    }
}
