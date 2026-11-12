//! Provider issuers: exchange a validated intent for a scoped, short-lived credential.
//!
//! Each issuer requests the *minimum* scope and returns a credential bound to the
//! request's `args_hash`. Providers that lack native per-request STS (e.g. Stripe) return
//! a broker-held grant with `proxy_required: true`.

pub mod aws_sts;
pub mod github;
pub mod mock;
pub mod stripe;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

/// A scoped request derived from the declared intent + policy decision.
#[derive(Debug, Clone)]
pub struct IssueRequest {
    pub tenant: String,
    pub agent_id: String,
    pub user_id: String,
    pub resource: String,
    pub scope: Vec<String>,
    pub ttl_seconds: u32,
    pub args_hash: String,
    pub args: serde_json::Value,
}

/// The secret material handed to the agent. Tagged so SDKs can branch on `kind`.
///
/// `Debug` is implemented manually to **redact** secrets so they never reach logs.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CredentialMaterial {
    /// AWS STS temporary credentials.
    AwsSts {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: String,
    },
    /// A bearer token (GitHub installation token, OAuth2 access token, ...).
    Bearer {
        token: String,
        expiration: Option<String>,
    },
    /// A broker-held secret that must be used via the Tessera proxy.
    Grant {
        grant_id: String,
        proxy_required: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralCredential {
    pub provider: String,
    pub resource: String,
    pub ttl_seconds: u32,
    pub single_use: bool,
    pub args_hash: String,
    pub material: CredentialMaterial,
    /// Broker-side reference for credential-level revocation (if the issuer supports it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Non-secret issuance id bound into the v2 receipt's credential thumbprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_id: Option<String>,
}

/// Outcome of a credential-level revocation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeEffect {
    Revoked,
    NotFound,
    Unsupported,
}

/// How the broker should reach a provider on the agent's behalf when the credential is a
/// broker-held grant (`proxy_required`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxySpec {
    pub base_url: String,
    pub auth_header: String,
    pub auth_scheme: String,
}

/// A redeemed grant: the secret plus how to use it. `Debug` redacts the secret.
#[derive(Clone)]
pub struct RedeemedGrant {
    pub secret: String,
    pub spec: ProxySpec,
    /// Resource the grant was issued for (empty when the issuer does not track it).
    pub resource: String,
    /// Authorization receipt bound at issuance (broker-held grants only).
    pub authorization_receipt_id: Option<String>,
    /// Action shared by the authorization and its outcome.
    pub action_id: Option<String>,
    /// Agent that requested the grant.
    pub agent_id: Option<String>,
}

impl std::fmt::Debug for CredentialMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialMaterial::AwsSts { access_key_id, .. } => f
                .debug_struct("AwsSts")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"<redacted>")
                .field("session_token", &"<redacted>")
                .finish(),
            CredentialMaterial::Bearer { .. } => f
                .debug_struct("Bearer")
                .field("token", &"<redacted>")
                .finish(),
            CredentialMaterial::Grant {
                grant_id,
                proxy_required,
            } => f
                .debug_struct("Grant")
                .field("grant_id", grant_id)
                .field("proxy_required", proxy_required)
                .finish(),
        }
    }
}

impl std::fmt::Debug for RedeemedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedeemedGrant")
            .field("secret", &"<redacted>")
            .field("base_url", &self.spec.base_url)
            .finish()
    }
}

#[async_trait]
pub trait Issuer: Send + Sync {
    fn provider(&self) -> &'static str;
    async fn issue(&self, req: &IssueRequest) -> Result<EphemeralCredential, BrokerError>;

    /// Redeem a broker-held grant (returns the secret + proxy spec). Issuers that do not
    /// use grants keep the default error. The tenant must match the one that issued it.
    async fn redeem_grant(
        &self,
        _tenant: &str,
        _grant_id: &str,
        _args_hash: &str,
    ) -> Result<RedeemedGrant, BrokerError> {
        Err(BrokerError::NotFound(
            "grant redemption is not supported by this issuer".into(),
        ))
    }

    /// Look up a grant's resource without consuming it (used to check API-key scope before
    /// redemption). Returns `None` when the issuer cannot answer.
    async fn peek_grant_resource(
        &self,
        _tenant: &str,
        _grant_id: &str,
    ) -> Result<Option<String>, BrokerError> {
        Ok(None)
    }

    /// Bind a broker-held grant to the authorization receipt that issued it.
    async fn bind_grant(
        &self,
        _tenant: &str,
        _grant_id: &str,
        _authorization_receipt_id: &str,
        _action_id: &str,
        _agent_id: &str,
    ) -> Result<bool, BrokerError> {
        Ok(false)
    }

    /// Attempt to invalidate a broker-held grant early. Returns whether it was revoked.
    async fn revoke_grant(&self, _tenant: &str, _grant_id: &str) -> Result<bool, BrokerError> {
        Ok(false)
    }

    /// Attempt provider-native revocation of an issued credential by reference.
    async fn revoke_credential(
        &self,
        _tenant: &str,
        _reference: &str,
    ) -> Result<RevokeEffect, BrokerError> {
        Ok(RevokeEffect::Unsupported)
    }
}

/// Maps a resource string (`provider:...`) to an issuer and issues credentials.
#[derive(Default)]
pub struct IssuerRegistry {
    issuers: HashMap<String, Arc<dyn Issuer>>,
}

impl IssuerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, issuer: Arc<dyn Issuer>) {
        self.issuers.insert(issuer.provider().to_string(), issuer);
    }

    pub fn get(&self, provider: &str) -> Option<Arc<dyn Issuer>> {
        self.issuers.get(provider).cloned()
    }

    pub fn providers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.issuers.keys().cloned().collect();
        v.sort();
        v
    }

    pub async fn exchange(
        &self,
        resource: &str,
        req: &IssueRequest,
    ) -> Result<EphemeralCredential, BrokerError> {
        let provider = provider_for(resource);
        let issuer = self
            .issuers
            .get(provider)
            .ok_or_else(|| BrokerError::Issuer(format!("no issuer for provider '{provider}'")))?;
        issuer.issue(req).await
    }

    /// Peek at a grant's resource without consuming it.
    pub async fn grant_resource(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> Result<Option<String>, BrokerError> {
        let Some(provider) = grant_provider(grant_id) else {
            return Ok(None);
        };
        let Some(issuer) = self.issuers.get(provider) else {
            return Ok(None);
        };
        issuer.peek_grant_resource(tenant, grant_id).await
    }

    /// Bind a broker-held grant to its authorization receipt.
    pub async fn bind_grant(
        &self,
        tenant: &str,
        grant_id: &str,
        authorization_receipt_id: &str,
        action_id: &str,
        agent_id: &str,
    ) -> Result<bool, BrokerError> {
        let Some(provider) = grant_provider(grant_id) else {
            return Ok(false);
        };
        let Some(issuer) = self.issuers.get(provider) else {
            return Ok(false);
        };
        issuer
            .bind_grant(
                tenant,
                grant_id,
                authorization_receipt_id,
                action_id,
                agent_id,
            )
            .await
    }

    /// Redeem a broker-held grant by looking up its provider from the grant id.
    pub async fn redeem(
        &self,
        tenant: &str,
        grant_id: &str,
        args_hash: &str,
    ) -> Result<RedeemedGrant, BrokerError> {
        let provider = grant_provider(grant_id)
            .ok_or_else(|| BrokerError::Invalid(format!("malformed grant id '{grant_id}'")))?;
        let issuer = self
            .issuers
            .get(provider)
            .ok_or_else(|| BrokerError::NotFound(format!("no issuer for provider '{provider}'")))?;
        issuer.redeem_grant(tenant, grant_id, args_hash).await
    }
}

/// The provider is the resource prefix, e.g. `stripe:refunds.create` -> `stripe`.
pub fn provider_for(resource: &str) -> &str {
    resource.split(':').next().unwrap_or(resource)
}

/// Normalize a tool (`stripe.refunds.create`) into a resource (`stripe:refunds.create`).
pub fn resource_from_tool(tool: &str) -> String {
    if tool.contains(':') {
        return tool.to_string();
    }
    match tool.split_once('.') {
        Some((provider, rest)) => format!("{provider}:{rest}"),
        None => tool.to_string(),
    }
}

/// Grant ids are `grant_<provider>_<opaque>`; extract the provider.
pub fn grant_provider(grant_id: &str) -> Option<&str> {
    let mut parts = grant_id.split('_');
    match (parts.next(), parts.next()) {
        (Some("grant"), Some(provider)) if !provider.is_empty() => Some(provider),
        _ => None,
    }
}

/// Credential references are `cred_<provider>_<opaque>`.
pub fn new_reference(provider: &str) -> String {
    format!("cred_{}_{}", provider, uuid::Uuid::new_v4().simple())
}

/// Extract the provider from a credential reference.
pub fn credential_provider(reference: &str) -> Option<&str> {
    let mut parts = reference.split('_');
    match (parts.next(), parts.next()) {
        (Some("cred"), Some(provider)) if !provider.is_empty() => Some(provider),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets() {
        let bearer = CredentialMaterial::Bearer {
            token: "super-secret-token".into(),
            expiration: None,
        };
        assert!(!format!("{bearer:?}").contains("super-secret-token"));

        let aws = CredentialMaterial::AwsSts {
            access_key_id: "AKIA".into(),
            secret_access_key: "SEKRET".into(),
            session_token: "SESSION".into(),
            expiration: "2026".into(),
        };
        let debug = format!("{aws:?}");
        assert!(!debug.contains("SEKRET") && !debug.contains("SESSION"));

        let grant = RedeemedGrant {
            secret: "rk_live_top".into(),
            spec: ProxySpec {
                base_url: "https://api.stripe.com".into(),
                auth_header: "authorization".into(),
                auth_scheme: "Bearer".into(),
            },
            resource: "stripe:refunds.create".into(),
            authorization_receipt_id: None,
            action_id: None,
            agent_id: None,
        };
        assert!(!format!("{grant:?}").contains("rk_live_top"));
    }

    #[test]
    fn resource_normalization() {
        assert_eq!(
            resource_from_tool("stripe.refunds.create"),
            "stripe:refunds.create"
        );
        assert_eq!(resource_from_tool("aws:s3:GetObject"), "aws:s3:GetObject");
        assert_eq!(resource_from_tool("standalone"), "standalone");
    }

    #[test]
    fn provider_extraction() {
        assert_eq!(provider_for("stripe:refunds.create"), "stripe");
        assert_eq!(provider_for("aws:s3:GetObject"), "aws");
    }

    #[test]
    fn grant_provider_parsing() {
        assert_eq!(grant_provider("grant_stripe_abc123"), Some("stripe"));
        assert_eq!(grant_provider("grant_github_1"), Some("github"));
        assert_eq!(grant_provider("grant_"), None);
        assert_eq!(grant_provider("notagrant"), None);
    }
}
