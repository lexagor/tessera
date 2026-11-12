//! GitHub App issuer — installation access token scoped to the minimum permissions.
//!
//! Flow: sign a short-lived RS256 JWT as the App, exchange it for an installation access
//! token via the GitHub API. The token inherits the installation's configured repository
//! and permission scope.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use super::{
    new_reference, CredentialMaterial, EphemeralCredential, IssueRequest, Issuer, RevokeEffect,
};
use crate::config::GithubConfig;
use crate::error::BrokerError;

struct Issued {
    installation_id: u64,
    tenant: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    #[allow(dead_code)]
    token: String,
}

/// Upper bound on tracked installation tokens.
const DEFAULT_MAX_ISSUED: usize = 50_000;

/// GitHub installation tokens expire after one hour and cannot be extended.
pub const GITHUB_MAX_TTL_SECONDS: u32 = 3600;

pub struct GithubIssuer {
    cfg: GithubConfig,
    client: reqwest::Client,
    issued: Arc<Mutex<HashMap<String, Issued>>>,
    max_issued: usize,
}

impl GithubIssuer {
    pub fn new(cfg: GithubConfig) -> Self {
        Self::with_max_issued(cfg, DEFAULT_MAX_ISSUED)
    }

    pub fn with_max_issued(cfg: GithubConfig, max_issued: usize) -> Self {
        Self {
            cfg,
            client: crate::netguard::outbound_client(),
            issued: Arc::new(Mutex::new(HashMap::new())),
            max_issued,
        }
    }

    /// Number of installation tokens currently tracked (ops/tests).
    pub fn issued_count(&self) -> usize {
        self.issued.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[derive(Debug, Serialize)]
struct AppClaims {
    iat: u64,
    exp: u64,
    iss: u64,
}

#[derive(Debug, Deserialize)]
struct InstallationToken {
    token: String,
    expires_at: Option<String>,
}

#[async_trait]
impl Issuer for GithubIssuer {
    fn provider(&self) -> &'static str {
        "github"
    }

    async fn issue(&self, req: &IssueRequest) -> Result<EphemeralCredential, BrokerError> {
        // GitHub installation tokens always expire after one hour; never claim a longer TTL
        // than the provider enforces.
        let ttl_seconds = req.ttl_seconds.clamp(1, GITHUB_MAX_TTL_SECONDS);
        let installation_id = req
            .args
            .get("installation_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                BrokerError::Issuer("github: args.installation_id is required".into())
            })?;

        let jwt = app_jwt(&self.cfg, chrono::Utc::now().timestamp() as u64)?;
        let url = installation_token_url(&self.cfg.api_base, installation_id);

        let resp = self
            .client
            .post(url)
            .header("authorization", format!("Bearer {jwt}"))
            .header("accept", "application/vnd.github+json")
            .header("user-agent", "tessera-broker")
            .send()
            .await
            .map_err(|e| BrokerError::Issuer(format!("github request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BrokerError::Issuer(format!(
                "github returned {status}: {}",
                body.chars().take(300).collect::<String>()
            )));
        }

        let parsed: InstallationToken = resp
            .json()
            .await
            .map_err(|e| BrokerError::Issuer(format!("github response parse failed: {e}")))?;

        let reference = new_reference(self.provider());
        let expires_at = parsed
            .expires_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1));

        if let Ok(mut issued) = self.issued.lock() {
            let now = chrono::Utc::now();
            issued.retain(|_, i| i.expires_at > now);
            if issued.len() >= self.max_issued {
                let mut by_expiry: Vec<(String, chrono::DateTime<chrono::Utc>)> = issued
                    .iter()
                    .map(|(k, v)| (k.clone(), v.expires_at))
                    .collect();
                by_expiry.sort_by_key(|(_, expires)| *expires);
                let to_remove = issued.len() - self.max_issued + 1;
                for (id, _) in by_expiry.into_iter().take(to_remove) {
                    issued.remove(&id);
                }
                tracing::warn!(
                    max_issued = self.max_issued,
                    "installation-token store at capacity; evicted soonest-expiring"
                );
            }
            issued.insert(
                reference.clone(),
                Issued {
                    installation_id,
                    tenant: req.tenant.clone(),
                    expires_at,
                    token: parsed.token.clone(),
                },
            );
        }

        Ok(EphemeralCredential {
            provider: self.provider().to_string(),
            resource: req.resource.clone(),
            ttl_seconds,
            single_use: false,
            args_hash: req.args_hash.clone(),
            material: CredentialMaterial::Bearer {
                token: parsed.token,
                expiration: parsed.expires_at,
            },
            reference: Some(reference),
            issuance_id: None,
        })
    }

    /// Revoke a previously issued installation token via the GitHub API (tenant-scoped).
    async fn revoke_credential(
        &self,
        tenant: &str,
        reference: &str,
    ) -> Result<RevokeEffect, BrokerError> {
        let installation_id = match self.issued.lock().ok().and_then(|m| {
            m.get(reference)
                .filter(|i| i.tenant == tenant)
                .map(|i| i.installation_id)
        }) {
            Some(id) => id,
            None => return Ok(RevokeEffect::NotFound),
        };

        let jwt = app_jwt(&self.cfg, chrono::Utc::now().timestamp() as u64)?;
        let url = revocation_url(&self.cfg.api_base, installation_id);
        let resp = self
            .client
            .delete(url)
            .header("authorization", format!("Bearer {jwt}"))
            .header("accept", "application/vnd.github+json")
            .header("user-agent", "tessera-broker")
            .send()
            .await
            .map_err(|e| BrokerError::Issuer(format!("github revoke failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(BrokerError::Issuer(format!(
                "github revoke returned {}",
                resp.status()
            )));
        }

        if let Ok(mut issued) = self.issued.lock() {
            issued.remove(reference);
        }
        Ok(RevokeEffect::Revoked)
    }
}

/// Build a GitHub App JWT (RS256), backdated 60s and valid for 9 minutes.
pub fn app_jwt(cfg: &GithubConfig, now: u64) -> Result<String, BrokerError> {
    let claims = AppClaims {
        iat: now.saturating_sub(60),
        exp: now + 540,
        iss: cfg.app_id,
    };
    let key = EncodingKey::from_rsa_pem(cfg.private_key_pem.as_bytes())
        .map_err(|e| BrokerError::Issuer(format!("invalid GitHub App private key: {e}")))?;
    encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| BrokerError::Issuer(format!("failed to encode GitHub App JWT: {e}")))
}

/// `POST {base}/app/installations/{id}/access_tokens`
pub fn installation_token_url(base: &str, installation_id: u64) -> String {
    format!(
        "{}/app/installations/{}/access_tokens",
        base.trim_end_matches('/'),
        installation_id
    )
}

/// `DELETE {base}/app/installations/{id}/access_tokens` (revokes installation tokens).
pub fn revocation_url(base: &str, installation_id: u64) -> String {
    installation_token_url(base, installation_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_construction() {
        assert_eq!(
            installation_token_url("https://api.github.com", 12345),
            "https://api.github.com/app/installations/12345/access_tokens"
        );
        assert_eq!(
            installation_token_url("https://ghe.example.com/api/v3/", 7),
            "https://ghe.example.com/api/v3/app/installations/7/access_tokens"
        );
    }
}
