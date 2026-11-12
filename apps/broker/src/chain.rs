//! Per-agent receipt chain, scoped to a tenant.
//!
//! Every authorization (allow or deny) and every recorded outcome is appended to a
//! tamper-evident chain for the acting agent. Each receipt's `prev` field is the
//! `payload_hash` of the preceding receipt, so removing, inserting, or reordering an entry
//! breaks both the signature check and the hash link.
//!
//! Chains are keyed by `(tenant, agent)`: two tenants may reuse an agent name without
//! sharing (or contaminating) each other's chains.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;
use crate::receipt::{GrantReceipt, ReceiptSigner};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Keccak-256 of the receipt's canonical payload (the value used as the next `prev`).
    pub payload_hash: String,
    pub receipt: GrantReceipt,
}

/// Result of an append attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    /// The stored head did not match `entry.receipt.prev`; the caller should re-read the
    /// head and retry.
    Conflict,
}

#[async_trait]
pub trait ChainStore: Send + Sync {
    async fn head_hash(&self, tenant: &str, agent: &str) -> Result<Option<String>, BrokerError>;

    /// Append an entry only if its `prev` matches the current head (optimistic append).
    async fn append(
        &self,
        tenant: &str,
        agent: &str,
        entry: ChainEntry,
    ) -> Result<AppendOutcome, BrokerError>;

    async fn find(
        &self,
        tenant: &str,
        agent: &str,
        payload_hash: &str,
    ) -> Result<Option<GrantReceipt>, BrokerError>;

    /// Find the recorded **outcome** for an authorization receipt: an entry that links to
    /// `prev_hash` *and* carries a result hash. A plain successor authorization also links to
    /// the previous receipt, so the result-hash filter is what distinguishes the two.
    async fn find_outcome(
        &self,
        tenant: &str,
        agent: &str,
        prev_hash: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        Ok(self
            .find_by_prev(tenant, agent, prev_hash)
            .await?
            .filter(|entry| entry.receipt.call.result_hash.is_some()))
    }

    /// Find the recorded outcome for an authorization receipt. New outcomes carry
    /// `authorizationReceiptId`, which survives later authorizations; old outcomes link
    /// immediately via `prev`.
    async fn find_outcome_for_authorization(
        &self,
        tenant: &str,
        agent: &str,
        authorization_receipt_id: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        if let Some(entry) = self.chain(tenant, agent).await?.into_iter().find(|entry| {
            entry.receipt.authorization_receipt_id.as_deref() == Some(authorization_receipt_id)
                && entry.receipt.call.result_hash.is_some()
        }) {
            return Ok(Some(entry));
        }
        Ok(self
            .find_outcome(tenant, agent, authorization_receipt_id)
            .await?
            .filter(|entry| entry.receipt.authorization_receipt_id.is_none()))
    }

    /// Find the entry whose receipt links to `prev_hash` (used by `record` to detect an
    /// existing outcome without materializing the whole chain).
    async fn find_by_prev(
        &self,
        tenant: &str,
        agent: &str,
        prev_hash: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        Ok(self
            .chain(tenant, agent)
            .await?
            .into_iter()
            .find(|entry| entry.receipt.prev.as_deref() == Some(prev_hash)))
    }

    async fn chain(&self, tenant: &str, agent: &str) -> Result<Vec<ChainEntry>, BrokerError>;

    async fn len(&self, tenant: &str, agent: &str) -> Result<usize, BrokerError>;

    /// Distinct tenants that have at least one receipt.
    async fn tenants(&self) -> Result<Vec<String>, BrokerError> {
        Ok(vec![])
    }

    /// Distinct agents belonging to a tenant.
    async fn agents_for_tenant(&self, _tenant: &str) -> Result<Vec<String>, BrokerError> {
        Ok(vec![])
    }

    /// Delete all receipts for agents whose latest receipt is older than `cutoff`.
    /// Whole-agent pruning keeps every remaining chain internally link-consistent.
    /// Returns the number of receipts removed.
    async fn prune_idle_agents(
        &self,
        _cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        Ok(0)
    }

    /// Prepare storage (no-op for in-memory).
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

type ChainKey = (String, String);

#[derive(Default)]
pub struct MemoryChainStore {
    chains: Mutex<HashMap<ChainKey, Vec<ChainEntry>>>,
}

impl MemoryChainStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<ChainKey, Vec<ChainEntry>>>, BrokerError> {
        self.chains
            .lock()
            .map_err(|_| BrokerError::Internal("receipt chain poisoned".into()))
    }
}

#[async_trait]
impl ChainStore for MemoryChainStore {
    async fn head_hash(&self, tenant: &str, agent: &str) -> Result<Option<String>, BrokerError> {
        let map = self.lock()?;
        Ok(map
            .get(&(tenant.to_string(), agent.to_string()))
            .and_then(|chain| chain.last())
            .map(|e| e.payload_hash.clone()))
    }

    async fn append(
        &self,
        tenant: &str,
        agent: &str,
        entry: ChainEntry,
    ) -> Result<AppendOutcome, BrokerError> {
        let mut map = self.lock()?;
        let chain = map
            .entry((tenant.to_string(), agent.to_string()))
            .or_default();
        let head = chain.last().map(|e| e.payload_hash.clone());
        if head != entry.receipt.prev {
            return Ok(AppendOutcome::Conflict);
        }
        chain.push(entry);
        Ok(AppendOutcome::Appended)
    }

    async fn find(
        &self,
        tenant: &str,
        agent: &str,
        payload_hash: &str,
    ) -> Result<Option<GrantReceipt>, BrokerError> {
        let map = self.lock()?;
        Ok(map
            .get(&(tenant.to_string(), agent.to_string()))
            .and_then(|chain| chain.iter().find(|e| e.payload_hash == payload_hash))
            .map(|e| e.receipt.clone()))
    }

    async fn find_by_prev(
        &self,
        tenant: &str,
        agent: &str,
        prev_hash: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        let map = self.lock()?;
        Ok(map
            .get(&(tenant.to_string(), agent.to_string()))
            .and_then(|chain| {
                chain
                    .iter()
                    .find(|entry| entry.receipt.prev.as_deref() == Some(prev_hash))
            })
            .cloned())
    }

    async fn chain(&self, tenant: &str, agent: &str) -> Result<Vec<ChainEntry>, BrokerError> {
        let map = self.lock()?;
        Ok(map
            .get(&(tenant.to_string(), agent.to_string()))
            .cloned()
            .unwrap_or_default())
    }

    async fn len(&self, tenant: &str, agent: &str) -> Result<usize, BrokerError> {
        Ok(self.chain(tenant, agent).await?.len())
    }

    async fn tenants(&self) -> Result<Vec<String>, BrokerError> {
        let map = self.lock()?;
        let mut tenants: Vec<String> = map.keys().map(|(tenant, _)| tenant.clone()).collect();
        tenants.sort();
        tenants.dedup();
        Ok(tenants)
    }

    async fn agents_for_tenant(&self, tenant: &str) -> Result<Vec<String>, BrokerError> {
        let map = self.lock()?;
        let mut agents: Vec<String> = map
            .keys()
            .filter(|(t, _)| t == tenant)
            .map(|(_, agent)| agent.clone())
            .collect();
        agents.sort();
        Ok(agents)
    }

    async fn prune_idle_agents(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        let mut map = self.lock()?;
        let mut removed = 0u64;
        map.retain(|_, chain| {
            let latest = chain
                .iter()
                .filter_map(|entry| chrono::DateTime::parse_from_rfc3339(&entry.receipt.ts).ok())
                .map(|ts| ts.with_timezone(&chrono::Utc))
                .max();
            match latest {
                Some(ts) if ts < cutoff => {
                    removed += chain.len() as u64;
                    false
                }
                _ => true,
            }
        });
        Ok(removed)
    }
}

/// Verify signatures and `prev` links across a chain.
///
/// Every receipt's signature must recover to the same signer address (recovered directly
/// from the signatures, so this works across restarts and key rotation), every `prev` link
/// must line up, and — when `expected` is provided — the recovered signer must match it.
pub fn verify_chain(
    chain: &[ChainEntry],
    signer: &ReceiptSigner,
    expected: Option<&str>,
) -> Result<bool, BrokerError> {
    let mut prev: Option<String> = None;
    let mut recovered: Option<String> = None;
    for entry in chain {
        let address = signer.recover(&entry.receipt)?;
        if let Some(expected) = expected {
            if !address.eq_ignore_ascii_case(expected) {
                return Ok(false);
            }
        }
        match &recovered {
            Some(first) if !address.eq_ignore_ascii_case(first) => return Ok(false),
            None => recovered = Some(address),
            _ => {}
        }
        if entry.receipt.prev != prev {
            return Ok(false);
        }
        prev = Some(entry.payload_hash.clone());
    }
    Ok(true)
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::canonical;
    use crate::receipt::{new_receipt, AuthorizationRef, CallRef, GrantReceipt, GrantRef};

    pub fn signer() -> crate::receipt::ReceiptSigner {
        crate::receipt::ReceiptSigner::from_hex_or_random(
            Some("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
            1,
            "0x0000000000000000000000000000000000000000",
        )
        .unwrap()
    }

    pub fn receipt_for(tenant: &str, agent: &str, tool: &str) -> GrantReceipt {
        new_receipt(
            tenant,
            agent,
            "u",
            canonical::keccak256_str("intent"),
            AuthorizationRef {
                decision: "allow".into(),
                policy: "p".into(),
                policy_version: 1,
                resource: tool.into(),
                anomaly_score: 0.0,
                policy_hash: None,
            },
            CallRef {
                tool: tool.into(),
                args_hash: canonical::keccak256_str(tool),
                result_hash: None,
                tool_hash: None,
            },
            GrantRef {
                provider: "mock".into(),
                ttl_s: 30,
                single_use: true,
                status: "issued".into(),
            },
        )
    }

    pub fn receipt(agent: &str, tool: &str) -> GrantReceipt {
        receipt_for("t", agent, tool)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{receipt, receipt_for, signer};
    use super::*;
    use crate::receipt::payload_hash_hex;

    async fn append(store: &dyn ChainStore, tenant: &str, agent: &str, tool: &str) -> ChainEntry {
        for _ in 0..8 {
            let head = store.head_hash(tenant, agent).await.unwrap();
            let mut r = receipt_for(tenant, agent, tool);
            r.prev = head;
            signer().sign(&mut r).await.unwrap();
            let entry = ChainEntry {
                payload_hash: payload_hash_hex(&r).unwrap(),
                receipt: r,
            };
            if store.append(tenant, agent, entry.clone()).await.unwrap() == AppendOutcome::Appended
            {
                return entry;
            }
        }
        panic!("append contention");
    }

    #[tokio::test]
    async fn links_prev_and_verifies() {
        let store = MemoryChainStore::new();
        let s = signer();
        let first = append(&store, "t", "a", "t1").await;
        let second = append(&store, "t", "a", "t2").await;
        assert!(first.receipt.prev.is_none());
        assert_eq!(
            second.receipt.prev.as_deref(),
            Some(first.payload_hash.as_str())
        );
        assert_eq!(store.len("t", "a").await.unwrap(), 2);
        assert!(verify_chain(
            &store.chain("t", "a").await.unwrap(),
            &s,
            Some(&s.address_hex())
        )
        .unwrap());
    }

    #[tokio::test]
    async fn chains_are_isolated_per_agent() {
        let store = MemoryChainStore::new();
        append(&store, "t", "a", "t").await;
        append(&store, "t", "b", "t").await;
        assert_eq!(store.len("t", "a").await.unwrap(), 1);
        assert_eq!(store.len("t", "b").await.unwrap(), 1);
    }

    /// Two tenants may reuse an agent id without sharing a chain.
    #[tokio::test]
    async fn chains_are_isolated_per_tenant() {
        let store = MemoryChainStore::new();
        append(&store, "tenant-a", "bot", "t1").await;
        append(&store, "tenant-a", "bot", "t2").await;
        append(&store, "tenant-b", "bot", "t1").await;

        assert_eq!(store.len("tenant-a", "bot").await.unwrap(), 2);
        assert_eq!(store.len("tenant-b", "bot").await.unwrap(), 1);
        assert!(store.head_hash("tenant-c", "bot").await.unwrap().is_none());
        assert_eq!(
            store.agents_for_tenant("tenant-a").await.unwrap(),
            vec!["bot".to_string()]
        );
        assert_eq!(
            store.tenants().await.unwrap(),
            vec!["tenant-a".to_string(), "tenant-b".to_string()]
        );
    }

    #[tokio::test]
    async fn find_by_payload_hash() {
        let store = MemoryChainStore::new();
        let entry = append(&store, "t", "a", "t1").await;
        let found = store
            .find("t", "a", &entry.payload_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.call.tool, "t1");
        assert!(store.find("t", "a", "0xdeadbeef").await.unwrap().is_none());
        // wrong tenant sees nothing
        assert!(store
            .find("other", "a", &entry.payload_hash)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn conflict_when_prev_does_not_match_head() {
        let store = MemoryChainStore::new();
        let first = append(&store, "t", "a", "t1").await;
        let mut stale = receipt("a", "t2");
        stale.prev = None;
        signer().sign(&mut stale).await.unwrap();
        let entry = ChainEntry {
            payload_hash: payload_hash_hex(&stale).unwrap(),
            receipt: stale,
        };
        assert_eq!(
            store.append("t", "a", entry).await.unwrap(),
            AppendOutcome::Conflict
        );
        assert_eq!(store.len("t", "a").await.unwrap(), 1);
        let _ = first;
    }

    #[tokio::test]
    async fn detects_tampering() {
        let store = MemoryChainStore::new();
        let s = signer();
        append(&store, "t", "a", "t1").await;
        append(&store, "t", "a", "t2").await;
        assert!(verify_chain(
            &store.chain("t", "a").await.unwrap(),
            &s,
            Some(&s.address_hex())
        )
        .unwrap());

        // Reordering breaks the prev links.
        {
            let mut map = store.chains.lock().unwrap();
            map.get_mut(&("t".to_string(), "a".to_string()))
                .unwrap()
                .reverse();
        }
        assert!(!verify_chain(
            &store.chain("t", "a").await.unwrap(),
            &s,
            Some(&s.address_hex())
        )
        .unwrap());

        // Restore order, then break a payload: signature check catches it.
        {
            let mut map = store.chains.lock().unwrap();
            let chain = map.get_mut(&("t".to_string(), "a".to_string())).unwrap();
            chain.reverse();
            chain[1].receipt.call.args_hash = "0xtampered".into();
        }
        assert!(!verify_chain(
            &store.chain("t", "a").await.unwrap(),
            &s,
            Some(&s.address_hex())
        )
        .unwrap());
    }

    #[tokio::test]
    async fn prune_idle_agents_removes_whole_agents() {
        let store = MemoryChainStore::new();
        append(&store, "t", "a", "t1").await;
        append(&store, "t", "a", "t2").await;
        append(&store, "t", "b", "t1").await;

        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        assert_eq!(store.prune_idle_agents(past).await.unwrap(), 0);
        assert_eq!(store.len("t", "a").await.unwrap(), 2);

        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        assert_eq!(store.prune_idle_agents(future).await.unwrap(), 3);
        assert_eq!(store.len("t", "a").await.unwrap(), 0);
        assert_eq!(store.len("t", "b").await.unwrap(), 0);
    }
}
