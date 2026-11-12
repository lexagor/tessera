//! Authority-token verification at the broker boundary.

use std::sync::Arc;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::cache::{Cache, MemoryCache};
use crate::canonical;
use crate::error::BrokerError;
use crate::receipt::PrincipalRef;

#[derive(Clone, Debug)]
pub struct AuthorityKey {
    pub kid: String,
    pub secret: String,
}

#[derive(Clone)]
pub struct AuthorityVerifier {
    pub keys: Vec<AuthorityKey>,
    pub issuer: String,
    pub audience: String,
    pub require_token: bool,
    pub replay: Arc<dyn Cache>,
}

impl Default for AuthorityVerifier {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            issuer: "tessera-api".to_string(),
            audience: "tessera-broker".to_string(),
            require_token: false,
            replay: Arc::new(MemoryCache::with_capacity(100_000)),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthorityClaims {
    sub: String,
    exp: usize,
    #[serde(default)]
    iat: Option<usize>,
    jti: String,
    #[serde(default)]
    authority_ref: Option<String>,
    #[serde(default)]
    principal_type: Option<String>,
    tenant: String,
    agent_id: String,
}

fn now_ts() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl AuthorityVerifier {
    /// Verify a token and return the principal it authorizes.
    ///
    /// `Ok(None)` means no token was supplied and the deployment does not require one.
    pub async fn verify(
        &self,
        token: Option<&str>,
        tenant: &str,
        agent_id: &str,
        caller_principal_id: Option<&str>,
        caller_principal_type: Option<&str>,
    ) -> Result<Option<PrincipalRef>, BrokerError> {
        let Some(token) = token else {
            if self.require_token {
                return Err(BrokerError::Invalid("authorityToken is required".into()));
            }
            return Ok(None);
        };
        if self.keys.is_empty() {
            return Err(BrokerError::Invalid(
                "authority token verification is not configured".into(),
            ));
        }
        for key in &self.keys {
            if key.secret.len() < 32 {
                return Err(BrokerError::Invalid(
                    "authority HMAC secret must be at least 32 bytes".into(),
                ));
            }
        }

        let header = decode_header(token)
            .map_err(|e| BrokerError::Invalid(format!("invalid authority token header: {e}")))?;
        let candidates: Vec<&AuthorityKey> = match header.kid.as_deref() {
            Some(kid) => self.keys.iter().filter(|key| key.kid == kid).collect(),
            None => self.keys.iter().collect(),
        };
        if candidates.is_empty() {
            return Err(BrokerError::Invalid(
                "authority token uses an unknown key id".into(),
            ));
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;

        let mut last_error = None;
        let mut claims = None;
        for key in candidates {
            match decode::<AuthorityClaims>(
                token,
                &DecodingKey::from_secret(key.secret.as_bytes()),
                &validation,
            ) {
                Ok(data) => {
                    claims = Some(data.claims);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let claims = claims.ok_or_else(|| {
            BrokerError::Invalid(format!(
                "invalid authority token: {}",
                last_error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "verification failed".to_string())
            ))
        })?;

        if claims.sub.is_empty() || claims.sub.len() > 256 {
            return Err(BrokerError::Invalid(
                "authority token subject must be 1..=256 bytes".into(),
            ));
        }
        if claims.tenant != tenant {
            return Err(BrokerError::Invalid(
                "authority token belongs to a different tenant".into(),
            ));
        }
        if claims.agent_id != agent_id {
            return Err(BrokerError::Invalid(
                "authority token belongs to a different agent".into(),
            ));
        }
        if claims.jti.is_empty() || claims.jti.len() > 256 {
            return Err(BrokerError::Invalid(
                "authority token jti must be 1..=256 bytes".into(),
            ));
        }
        if let Some(kind) = &claims.principal_type {
            if kind.is_empty() || kind.len() > 64 {
                return Err(BrokerError::Invalid(
                    "authority token principal_type must be 1..=64 bytes".into(),
                ));
            }
        }
        if let Some(reference) = claims.authority_ref.as_ref() {
            if reference.is_empty() || reference.len() > 512 {
                return Err(BrokerError::Invalid(
                    "authority token authority_ref must be 1..=512 bytes".into(),
                ));
            }
        }
        if let Some(principal_id) = caller_principal_id {
            if principal_id != claims.sub {
                return Err(BrokerError::Invalid(
                    "authority token subject does not match principalId".into(),
                ));
            }
        }

        let now = chrono::Utc::now().timestamp();
        if claims.exp as i64 <= now {
            return Err(BrokerError::Invalid("authority token is expired".into()));
        }
        if claims.exp as i64 > now + 86_400 {
            return Err(BrokerError::Invalid(
                "authority token expiry must be within 24 hours".into(),
            ));
        }
        if let Some(iat) = claims.iat {
            if iat as i64 > now + 300 {
                return Err(BrokerError::Invalid(
                    "authority token iat is in the future".into(),
                ));
            }
        }

        let replay_key = format!("tessera:authority:jti:{tenant}:{}", claims.jti);
        let ttl = (claims.exp as i64 - now).clamp(1, 86_400) as u64;
        if !self.replay.put_if_absent(&replay_key, "1", ttl).await? {
            return Err(BrokerError::Invalid(
                "authority token has already been used".into(),
            ));
        }

        let authority_ref = claims.authority_ref.unwrap_or_else(|| claims.jti.clone());
        Ok(Some(PrincipalRef {
            principal_id: claims.sub,
            principal_type: claims
                .principal_type
                .or_else(|| caller_principal_type.map(str::to_string))
                .unwrap_or_else(|| "user".to_string()),
            authority_ref,
            authority_hash: canonical::keccak256_str(token),
            verified_at: Some(now_ts()),
            verification_method: "hmac-jwt".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};

    use super::*;

    const SECRET: &str = "tessera-test-authority-secret-32-bytes-minimum";

    fn verifier() -> AuthorityVerifier {
        AuthorityVerifier {
            keys: vec![AuthorityKey {
                kid: "v1".to_string(),
                secret: SECRET.to_string(),
            }],
            require_token: true,
            ..Default::default()
        }
    }

    fn token(claims: serde_json::Value, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(str::to_string);
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    }

    fn claims(jti: &str) -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "iss": "tessera-api",
            "aud": "tessera-broker",
            "sub": "user_42",
            "exp": now + 60,
            "iat": now,
            "jti": jti,
            "tenant": "acme",
            "agent_id": "billing-agent"
        })
    }

    #[tokio::test]
    async fn verifies_and_rejects_replay() {
        let verifier = verifier();
        let token = token(claims("jti-1"), Some("v1"));
        let principal = verifier
            .verify(Some(&token), "acme", "billing-agent", None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.principal_id, "user_42");
        assert_eq!(principal.verification_method, "hmac-jwt");

        let replay = verifier
            .verify(Some(&token), "acme", "billing-agent", None, None)
            .await
            .unwrap_err();
        assert!(matches!(replay, BrokerError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_wrong_scope_and_audience() {
        let verifier = verifier();
        let wrong_tenant = token(claims("jti-2"), Some("v1"));
        assert!(verifier
            .verify(Some(&wrong_tenant), "other", "billing-agent", None, None)
            .await
            .is_err());

        let wrong_agent = token(claims("jti-3"), Some("v1"));
        assert!(verifier
            .verify(Some(&wrong_agent), "acme", "other-agent", None, None)
            .await
            .is_err());

        let mut bad_aud = claims("jti-4");
        bad_aud["aud"] = serde_json::json!("other-service");
        let bad_aud = token(bad_aud, Some("v1"));
        assert!(verifier
            .verify(Some(&bad_aud), "acme", "billing-agent", None, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_previous_kid_during_rotation() {
        let mut verifier = verifier();
        verifier.keys.push(AuthorityKey {
            kid: "v0".to_string(),
            secret: "tessera-previous-authority-secret-32-bytes-min".to_string(),
        });
        let now = chrono::Utc::now().timestamp();
        let old = serde_json::json!({
            "iss": "tessera-api",
            "aud": "tessera-broker",
            "sub": "user_42",
            "exp": now + 60,
            "iat": now,
            "jti": "jti-old",
            "tenant": "acme",
            "agent_id": "billing-agent"
        });
        let old = encode(
            &Header::new(Algorithm::HS256),
            &old,
            &EncodingKey::from_secret("tessera-previous-authority-secret-32-bytes-min".as_bytes()),
        )
        .unwrap();
        assert!(verifier
            .verify(Some(&old), "acme", "billing-agent", None, None)
            .await
            .unwrap()
            .is_some());
    }
}
