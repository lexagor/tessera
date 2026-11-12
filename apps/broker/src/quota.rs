//! Provider quota reservations: in-flight caps so one tenant's burst cannot exhaust a
//! shared upstream limit.
//!
//! Two levels per provider: a provider-wide cap and a per-tenant cap. Permits are released
//! when the guard is dropped, so a failed or cancelled call cannot leak capacity. Disabled
//! by default (cap 0 = unlimited).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::BrokerError;

/// Maximum number of tenants tracked for per-tenant caps (bounded memory).
const MAX_TRACKED_TENANTS: usize = 10_000;

pub struct QuotaManager {
    /// Provider -> provider-wide semaphore.
    global: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Provider -> tenant -> semaphore.
    per_tenant: Mutex<HashMap<String, HashMap<String, Arc<Semaphore>>>>,
    global_cap: usize,
    per_tenant_cap: usize,
}

/// Held for the duration of a provider call; dropping it releases the reservation.
pub struct QuotaPermit {
    _global: Option<OwnedSemaphorePermit>,
    _tenant: Option<OwnedSemaphorePermit>,
}

impl QuotaManager {
    pub fn new(global_cap: usize, per_tenant_cap: usize) -> Self {
        Self {
            global: Mutex::new(HashMap::new()),
            per_tenant: Mutex::new(HashMap::new()),
            global_cap,
            per_tenant_cap,
        }
    }

    pub fn disabled() -> Self {
        Self::new(0, 0)
    }

    pub fn is_enabled(&self) -> bool {
        self.global_cap > 0 || self.per_tenant_cap > 0
    }

    fn lock_global(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Arc<Semaphore>>>, BrokerError> {
        self.global
            .lock()
            .map_err(|_| BrokerError::Internal("quota manager poisoned".into()))
    }

    /// Current reservations per provider (for dashboards and support).
    pub fn snapshot(&self) -> Vec<serde_json::Value> {
        let global = match self.lock_global() {
            Ok(global) => global,
            Err(_) => return Vec::new(),
        };
        let per_tenant = match self.per_tenant.lock() {
            Ok(per_tenant) => per_tenant,
            Err(_) => return Vec::new(),
        };
        let mut providers: Vec<String> = global.keys().cloned().collect();
        for provider in per_tenant.keys() {
            if !providers.iter().any(|existing| existing == provider) {
                providers.push(provider.clone());
            }
        }
        providers.sort();
        providers
            .into_iter()
            .map(|provider| {
                let global_semaphore = global.get(&provider);
                let in_flight = global_semaphore
                    .map(|semaphore| {
                        self.global_cap
                            .saturating_sub(semaphore.available_permits())
                    })
                    .unwrap_or(0);
                let tenants = per_tenant
                    .get(&provider)
                    .map(|tenants| tenants.len())
                    .unwrap_or(0);
                serde_json::json!({
                    "provider": provider,
                    "maxInflight": self.global_cap,
                    "inFlight": in_flight,
                    "perTenantMaxInflight": self.per_tenant_cap,
                    "tenantsTracked": tenants,
                })
            })
            .collect()
    }

    /// Reserve capacity for one provider call. Returns a permit (released on drop) or a
    /// throttle error when the reservation would be exceeded.
    pub fn acquire(&self, provider: &str, tenant: &str) -> Result<QuotaPermit, BrokerError> {
        if !self.is_enabled() {
            return Ok(QuotaPermit {
                _global: None,
                _tenant: None,
            });
        }

        let global_permit = if self.global_cap > 0 {
            let semaphore = {
                let mut global = self.lock_global()?;
                global
                    .entry(provider.to_string())
                    .or_insert_with(|| Arc::new(Semaphore::new(self.global_cap)))
                    .clone()
            };
            match semaphore.try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    crate::metrics::quota_rejection();
                    return Err(BrokerError::Throttled(format!(
                        "provider '{provider}' is at its in-flight capacity"
                    )));
                }
            }
        } else {
            None
        };

        let tenant_permit = if self.per_tenant_cap > 0 {
            let semaphore = {
                let mut per_tenant = self
                    .per_tenant
                    .lock()
                    .map_err(|_| BrokerError::Internal("quota manager poisoned".into()))?;
                if per_tenant.len() >= MAX_TRACKED_TENANTS && !per_tenant.contains_key(provider) {
                    crate::metrics::quota_rejection();
                    return Err(BrokerError::Throttled(
                        "quota manager at tenant capacity".into(),
                    ));
                }
                per_tenant
                    .entry(provider.to_string())
                    .or_default()
                    .entry(tenant.to_string())
                    .or_insert_with(|| Arc::new(Semaphore::new(self.per_tenant_cap)))
                    .clone()
            };
            match semaphore.try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    crate::metrics::quota_rejection();
                    return Err(BrokerError::Throttled(format!(
                        "tenant '{tenant}' is at its in-flight capacity for provider '{provider}'"
                    )));
                }
            }
        } else {
            None
        };

        Ok(QuotaPermit {
            _global: global_permit,
            _tenant: tenant_permit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_are_enforced_per_provider_and_per_tenant() {
        let quota = QuotaManager::new(3, 1);

        // Tenant A holds its single slot.
        let a1 = quota.acquire("stripe", "tenant-a").unwrap();
        let err = quota
            .acquire("stripe", "tenant-a")
            .err()
            .expect("throttled");
        assert!(matches!(err, BrokerError::Throttled(_)));

        // Tenant B is unaffected by A's usage.
        let b1 = quota.acquire("stripe", "tenant-b").unwrap();
        // Provider-wide cap still has room for one more tenant.
        let c1 = quota.acquire("stripe", "tenant-c").unwrap();
        // ...and now the provider cap (3) is reached.
        let err = quota
            .acquire("stripe", "tenant-d")
            .err()
            .expect("throttled");
        assert!(matches!(err, BrokerError::Throttled(_)));

        // Another provider is independent.
        let aws = quota.acquire("aws", "tenant-d").unwrap();

        // Dropping a permit frees the reservation.
        drop(b1);
        quota.acquire("stripe", "tenant-d").unwrap();

        drop((a1, c1, aws));
        quota.acquire("stripe", "tenant-d").unwrap();
    }

    #[test]
    fn snapshot_reports_reservations() {
        let quota = QuotaManager::new(3, 1);
        assert!(quota.snapshot().is_empty());

        let _a = quota.acquire("stripe", "tenant-a").unwrap();
        let _b = quota.acquire("stripe", "tenant-b").unwrap();
        let _c = quota.acquire("aws", "tenant-a").unwrap();

        let snapshot = quota.snapshot();
        assert_eq!(snapshot.len(), 2);
        let stripe = snapshot
            .iter()
            .find(|entry| entry["provider"] == "stripe")
            .unwrap();
        assert_eq!(stripe["inFlight"], 2);
        assert_eq!(stripe["maxInflight"], 3);
        assert_eq!(stripe["perTenantMaxInflight"], 1);
        assert_eq!(stripe["tenantsTracked"], 2);
        let aws = snapshot
            .iter()
            .find(|entry| entry["provider"] == "aws")
            .unwrap();
        assert_eq!(aws["inFlight"], 1);
    }

    #[test]
    fn disabled_manager_never_blocks() {
        let quota = QuotaManager::disabled();
        assert!(!quota.is_enabled());
        for _ in 0..1000 {
            let _permit = quota.acquire("stripe", "tenant-a").unwrap();
        }
    }
}
