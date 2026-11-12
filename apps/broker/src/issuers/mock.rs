//! Mock issuer for tests and local development without live provider credentials.

use async_trait::async_trait;

use super::{CredentialMaterial, EphemeralCredential, IssueRequest, Issuer};
use crate::error::BrokerError;

pub struct MockIssuer {
    name: &'static str,
}

impl MockIssuer {
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }
}

#[async_trait]
impl Issuer for MockIssuer {
    fn provider(&self) -> &'static str {
        self.name
    }

    async fn issue(&self, req: &IssueRequest) -> Result<EphemeralCredential, BrokerError> {
        Ok(EphemeralCredential {
            provider: self.provider().to_string(),
            resource: req.resource.clone(),
            ttl_seconds: req.ttl_seconds,
            single_use: true,
            args_hash: req.args_hash.clone(),
            material: CredentialMaterial::Bearer {
                token: format!("mock-{}-{}", self.name, req.args_hash),
                expiration: None,
            },
            reference: None,
            issuance_id: None,
        })
    }
}
