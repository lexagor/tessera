//! Per-tenant auto-remediation policy: keep newly created or widened keys inside a template.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationPolicy {
    /// Template name that over-granted keys are narrowed to.
    pub template: String,
    /// Preset revision the policy was approved against. `None` accepts the current revision
    /// (legacy policies); a mismatch makes the policy stale and it stops acting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_version: Option<u32>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub updated_at: String,
}

fn default_enabled() -> bool {
    true
}

#[async_trait]
pub trait RemediationPolicyStore: Send + Sync {
    async fn set(&self, tenant: &str, policy: RemediationPolicy) -> Result<(), BrokerError>;
    async fn get(&self, tenant: &str) -> Result<Option<RemediationPolicy>, BrokerError>;
    async fn delete(&self, tenant: &str) -> Result<bool, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryRemediationPolicies {
    policies: Mutex<HashMap<String, RemediationPolicy>>,
}

impl MemoryRemediationPolicies {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RemediationPolicyStore for MemoryRemediationPolicies {
    async fn set(&self, tenant: &str, policy: RemediationPolicy) -> Result<(), BrokerError> {
        self.policies
            .lock()
            .map_err(|_| BrokerError::Internal("remediation policy store poisoned".into()))?
            .insert(tenant.to_string(), policy);
        Ok(())
    }

    async fn get(&self, tenant: &str) -> Result<Option<RemediationPolicy>, BrokerError> {
        Ok(self
            .policies
            .lock()
            .map_err(|_| BrokerError::Internal("remediation policy store poisoned".into()))?
            .get(tenant)
            .cloned())
    }

    async fn delete(&self, tenant: &str) -> Result<bool, BrokerError> {
        Ok(self
            .policies
            .lock()
            .map_err(|_| BrokerError::Internal("remediation policy store poisoned".into()))?
            .remove(tenant)
            .is_some())
    }
}
