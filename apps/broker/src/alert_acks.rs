//! Alert acknowledgements: a tenant acknowledges the current condition so repeated alerts
//! stop until that condition gets worse (or clears and recurs).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

/// An acknowledgement of an alert condition at a given severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertAck {
    pub event: String,
    pub dedup_key: String,
    /// Condition value at acknowledgement time; alerts re-fire only above this.
    pub value: u64,
    pub acked_at: String,
}

#[async_trait]
pub trait AlertAckStore: Send + Sync {
    async fn set(&self, tenant: &str, ack: AlertAck) -> Result<(), BrokerError>;
    async fn get(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
    ) -> Result<Option<AlertAck>, BrokerError>;
    async fn delete(&self, tenant: &str, event: &str, dedup_key: &str)
        -> Result<bool, BrokerError>;
    /// Remove every ack for an event except those in `keep` (called when conditions clear).
    async fn retain(&self, tenant: &str, event: &str, keep: &[String]) -> Result<u64, BrokerError>;
    async fn list(&self, tenant: &str) -> Result<Vec<AlertAck>, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

/// (tenant, event, dedup key) -> ack.
type AckKey = (String, String, String);

#[derive(Default)]
pub struct MemoryAlertAcks {
    acks: Mutex<HashMap<AckKey, AlertAck>>,
}

impl MemoryAlertAcks {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<AckKey, AlertAck>>, BrokerError> {
        self.acks
            .lock()
            .map_err(|_| BrokerError::Internal("alert ack store poisoned".into()))
    }
}

#[async_trait]
impl AlertAckStore for MemoryAlertAcks {
    async fn set(&self, tenant: &str, ack: AlertAck) -> Result<(), BrokerError> {
        self.lock()?.insert(
            (tenant.to_string(), ack.event.clone(), ack.dedup_key.clone()),
            ack,
        );
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
    ) -> Result<Option<AlertAck>, BrokerError> {
        Ok(self
            .lock()?
            .get(&(tenant.to_string(), event.to_string(), dedup_key.to_string()))
            .cloned())
    }

    async fn delete(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
    ) -> Result<bool, BrokerError> {
        Ok(self
            .lock()?
            .remove(&(tenant.to_string(), event.to_string(), dedup_key.to_string()))
            .is_some())
    }

    async fn retain(&self, tenant: &str, event: &str, keep: &[String]) -> Result<u64, BrokerError> {
        let mut acks = self.lock()?;
        let before = acks.len();
        acks.retain(|(t, e, dedup), _| {
            t != tenant || e != event || keep.iter().any(|candidate| candidate == dedup)
        });
        Ok((before - acks.len()) as u64)
    }

    async fn list(&self, tenant: &str) -> Result<Vec<AlertAck>, BrokerError> {
        let mut acks: Vec<AlertAck> = self
            .lock()?
            .iter()
            .filter(|((t, _, _), _)| t == tenant)
            .map(|(_, ack)| ack.clone())
            .collect();
        acks.sort_by(|a, b| b.acked_at.cmp(&a.acked_at));
        Ok(acks)
    }
}

/// Whether an alert with `condition_value` should fire given a prior ack.
pub fn should_fire(ack: Option<&AlertAck>, condition_value: u64) -> bool {
    match ack {
        Some(ack) => condition_value > ack.value,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(value: u64) -> AlertAck {
        AlertAck {
            event: "anchor.gap".into(),
            dedup_key: "agent-1".into(),
            value,
            acked_at: "2026-09-17T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn acked_conditions_stay_quiet_until_worse() {
        let store = MemoryAlertAcks::new();
        store.set("acme", ack(5)).await.unwrap();

        let current = store.get("acme", "anchor.gap", "agent-1").await.unwrap();
        assert!(
            !should_fire(current.as_ref(), 5),
            "same severity stays quiet"
        );
        assert!(!should_fire(current.as_ref(), 4), "improved stays quiet");
        assert!(should_fire(current.as_ref(), 6), "worse fires again");

        // Clearing the condition removes the ack so a recurrence alerts.
        let removed = store.retain("acme", "anchor.gap", &[]).await.unwrap();
        assert_eq!(removed, 1);
        assert!(store
            .get("acme", "anchor.gap", "agent-1")
            .await
            .unwrap()
            .is_none());
        assert!(should_fire(None, 1));
    }

    #[tokio::test]
    async fn retain_keeps_active_conditions() {
        let store = MemoryAlertAcks::new();
        store.set("acme", ack(5)).await.unwrap();
        store
            .set(
                "acme",
                AlertAck {
                    event: "anchor.gap".into(),
                    dedup_key: "agent-2".into(),
                    ..ack(2)
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .retain("acme", "anchor.gap", &["agent-2".to_string()])
                .await
                .unwrap(),
            1
        );
        assert!(store
            .get("acme", "anchor.gap", "agent-2")
            .await
            .unwrap()
            .is_some());
    }
}
