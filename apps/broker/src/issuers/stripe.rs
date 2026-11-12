//! Stripe issuer — restricted-key selection + a broker-held single-use grant.
//!
//! Stripe has no per-request STS, so the broker holds the narrowest restricted key and
//! returns an opaque grant id. The secret is released only through the Tessera proxy,
//! after re-checking that the arguments still match `args_hash`.
//!
//! Grants can be held in memory (default) or in Postgres (`DATABASE_URL` +
//! `TENANT_SECRET_ENC_KEY`), so a restart or a second broker replica can still redeem a
//! grant issued by another process. The persisted secret is envelope-encrypted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use super::{
    CredentialMaterial, EphemeralCredential, IssueRequest, Issuer, ProxySpec, RedeemedGrant,
};
use crate::config::StripeConfig;
use crate::error::BrokerError;
use crate::secrets::Envelope;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredGrant {
    pub secret_key: String,
    pub tenant: String,
    pub resource: String,
    pub args_hash: String,
    pub expires_at: DateTime<Utc>,
    pub spec: ProxySpec,
    #[serde(default)]
    pub authorization_receipt_id: Option<String>,
    #[serde(default)]
    pub action_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// Upper bound on live grants held in memory; the soonest-expiring are evicted beyond this.
const DEFAULT_MAX_GRANTS: usize = 50_000;

#[async_trait]
pub trait GrantStore: Send + Sync {
    async fn insert(&self, grant_id: String, grant: StoredGrant) -> Result<(), BrokerError>;
    async fn peek(&self, tenant: &str, grant_id: &str) -> Result<Option<String>, BrokerError>;
    async fn redeem(
        &self,
        tenant: &str,
        grant_id: &str,
        args_hash: &str,
    ) -> Result<RedeemedGrant, BrokerError>;
    async fn bind(
        &self,
        tenant: &str,
        grant_id: &str,
        authorization_receipt_id: &str,
        action_id: &str,
        agent_id: &str,
    ) -> Result<bool, BrokerError>;
    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, BrokerError>;
    async fn count(&self) -> Result<usize, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

/// In-process grant store. Bounded and single-use, but not durable across restarts or
/// replicas; use [`PostgresGrantStore`] in production.
pub struct MemoryGrantStore {
    grants: Mutex<HashMap<String, StoredGrant>>,
    max_grants: usize,
}

impl MemoryGrantStore {
    pub fn new(max_grants: usize) -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
            max_grants,
        }
    }

    fn prune(grants: &mut HashMap<String, StoredGrant>, max_grants: usize) {
        let now = Utc::now();
        grants.retain(|_, g| g.expires_at > now);
        if grants.len() >= max_grants {
            let mut by_expiry: Vec<(String, DateTime<Utc>)> = grants
                .iter()
                .map(|(id, g)| (id.clone(), g.expires_at))
                .collect();
            by_expiry.sort_by_key(|(_, expires)| *expires);
            let to_remove = grants.len() - max_grants + 1;
            for (id, _) in by_expiry.into_iter().take(to_remove) {
                grants.remove(&id);
            }
            tracing::warn!(
                max_grants,
                "grant store at capacity; evicted soonest-expiring grants"
            );
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, StoredGrant>>, BrokerError> {
        self.grants
            .lock()
            .map_err(|_| BrokerError::Internal("grant store poisoned".into()))
    }
}

#[async_trait]
impl GrantStore for MemoryGrantStore {
    async fn insert(&self, grant_id: String, grant: StoredGrant) -> Result<(), BrokerError> {
        let mut grants = self.lock()?;
        Self::prune(&mut grants, self.max_grants);
        grants.insert(grant_id, grant);
        Ok(())
    }

    async fn peek(&self, tenant: &str, grant_id: &str) -> Result<Option<String>, BrokerError> {
        let grants = self.lock()?;
        Ok(grants
            .get(grant_id)
            .filter(|grant| grant.tenant == tenant && grant.expires_at > Utc::now())
            .map(|grant| grant.resource.clone()))
    }

    async fn redeem(
        &self,
        tenant: &str,
        grant_id: &str,
        args_hash: &str,
    ) -> Result<RedeemedGrant, BrokerError> {
        let mut grants = self.lock()?;
        let grant = grants
            .get(grant_id)
            .ok_or_else(|| BrokerError::NotFound(format!("grant {grant_id}")))?;
        if grant.tenant != tenant {
            return Err(BrokerError::NotFound(format!("grant {grant_id}")));
        }
        if grant.args_hash != args_hash {
            return Err(BrokerError::Denied("grant args hash mismatch".into()));
        }
        if grant.expires_at < Utc::now() {
            grants.remove(grant_id);
            return Err(BrokerError::Denied("grant expired".into()));
        }
        let redeemed = RedeemedGrant {
            secret: grant.secret_key.clone(),
            spec: grant.spec.clone(),
            resource: grant.resource.clone(),
            authorization_receipt_id: grant.authorization_receipt_id.clone(),
            action_id: grant.action_id.clone(),
            agent_id: grant.agent_id.clone(),
        };
        grants.remove(grant_id);
        Ok(redeemed)
    }

    async fn bind(
        &self,
        tenant: &str,
        grant_id: &str,
        authorization_receipt_id: &str,
        action_id: &str,
        agent_id: &str,
    ) -> Result<bool, BrokerError> {
        let mut grants = self.lock()?;
        let Some(grant) = grants.get_mut(grant_id) else {
            return Ok(false);
        };
        if grant.tenant != tenant {
            return Ok(false);
        }
        grant.authorization_receipt_id = Some(authorization_receipt_id.to_string());
        grant.action_id = Some(action_id.to_string());
        grant.agent_id = Some(agent_id.to_string());
        Ok(true)
    }

    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, BrokerError> {
        let mut grants = self.lock()?;
        match grants.get(grant_id) {
            Some(grant) if grant.tenant == tenant => Ok(grants.remove(grant_id).is_some()),
            _ => Ok(false),
        }
    }

    async fn count(&self) -> Result<usize, BrokerError> {
        Ok(self.lock()?.len())
    }
}

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS stripe_grants (
    grant_id         TEXT        PRIMARY KEY,
    tenant           TEXT        NOT NULL,
    resource         TEXT        NOT NULL,
    args_hash        TEXT        NOT NULL,
    secret_ciphertext TEXT       NOT NULL,
    spec             JSONB       NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    authorization_receipt_id TEXT,
    action_id        TEXT,
    agent_id         TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE stripe_grants ADD COLUMN IF NOT EXISTS authorization_receipt_id TEXT;
ALTER TABLE stripe_grants ADD COLUMN IF NOT EXISTS action_id TEXT;
ALTER TABLE stripe_grants ADD COLUMN IF NOT EXISTS agent_id TEXT;
CREATE INDEX IF NOT EXISTS stripe_grants_tenant_expiry_idx
    ON stripe_grants (tenant, expires_at);
CREATE INDEX IF NOT EXISTS stripe_grants_authorization_idx
    ON stripe_grants (tenant, authorization_receipt_id)
    WHERE authorization_receipt_id IS NOT NULL;
"#;

/// Durable grant store. Secrets are envelope-encrypted with `TENANT_SECRET_ENC_KEY`.
pub struct PostgresGrantStore {
    pool: PgPool,
    envelope: Arc<Envelope>,
    max_grants: usize,
}

impl PostgresGrantStore {
    pub fn new(url: &str, envelope: Option<Arc<Envelope>>) -> Result<Self, BrokerError> {
        Self::with_max_grants(url, envelope, DEFAULT_MAX_GRANTS)
    }

    pub fn with_max_grants(
        url: &str,
        envelope: Option<Arc<Envelope>>,
        max_grants: usize,
    ) -> Result<Self, BrokerError> {
        let envelope = envelope.ok_or_else(|| {
            BrokerError::Invalid(
                "TENANT_SECRET_ENC_KEY is required for durable Stripe grants".into(),
            )
        })?;
        Ok(Self {
            pool: crate::db::connect_pool(url, 5)?,
            envelope,
            max_grants,
        })
    }

    /// Remove all rows (test helper).
    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM stripe_grants")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl GrantStore for PostgresGrantStore {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn insert(&self, grant_id: String, grant: StoredGrant) -> Result<(), BrokerError> {
        let secret = self.envelope.encrypt(&grant.secret_key)?;
        let spec = serde_json::to_value(&grant.spec)
            .map_err(|e| BrokerError::Internal(format!("serialize grant spec: {e}")))?;
        sqlx::query(
            "INSERT INTO stripe_grants
                (grant_id, tenant, resource, args_hash, secret_ciphertext, spec, expires_at,
                 authorization_receipt_id, action_id, agent_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&grant_id)
        .bind(&grant.tenant)
        .bind(&grant.resource)
        .bind(&grant.args_hash)
        .bind(secret)
        .bind(sqlx::types::Json(spec))
        .bind(grant.expires_at)
        .bind(grant.authorization_receipt_id.as_deref())
        .bind(grant.action_id.as_deref())
        .bind(grant.agent_id.as_deref())
        .execute(&self.pool)
        .await
        .map_err(map)?;
        // Opportunistic cleanup; redemption remains authoritative for expiry.
        sqlx::query("DELETE FROM stripe_grants WHERE expires_at <= now()")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        // Keep the durable store bounded like the in-memory store. This evicts the
        // soonest-expiring grants across tenants when the cap is exceeded.
        sqlx::query(
            "DELETE FROM stripe_grants
              WHERE grant_id IN (
                SELECT grant_id FROM stripe_grants
                 ORDER BY expires_at ASC
                 LIMIT GREATEST((SELECT count(*) FROM stripe_grants) - $1, 0)
              )",
        )
        .bind(self.max_grants as i64)
        .execute(&self.pool)
        .await
        .map_err(map)?;
        Ok(())
    }

    async fn peek(&self, tenant: &str, grant_id: &str) -> Result<Option<String>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT resource FROM stripe_grants
              WHERE grant_id = $1 AND tenant = $2 AND expires_at > now()",
        )
        .bind(grant_id)
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(row.map(|row| row.get::<String, _>("resource")))
    }

    async fn redeem(
        &self,
        tenant: &str,
        grant_id: &str,
        args_hash: &str,
    ) -> Result<RedeemedGrant, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT resource, args_hash, secret_ciphertext, spec, expires_at,
                    authorization_receipt_id, action_id, agent_id
               FROM stripe_grants
              WHERE grant_id = $1 AND tenant = $2
              FOR UPDATE",
        )
        .bind(grant_id)
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        let Some(row) = row else {
            tx.commit().await.map_err(map)?;
            return Err(BrokerError::NotFound(format!("grant {grant_id}")));
        };
        let expires_at: DateTime<Utc> = row.get("expires_at");
        if expires_at < Utc::now() {
            sqlx::query("DELETE FROM stripe_grants WHERE grant_id = $1")
                .bind(grant_id)
                .execute(&mut *tx)
                .await
                .map_err(map)?;
            tx.commit().await.map_err(map)?;
            return Err(BrokerError::Denied("grant expired".into()));
        }
        if row.get::<String, _>("args_hash") != args_hash {
            tx.commit().await.map_err(map)?;
            return Err(BrokerError::Denied("grant args hash mismatch".into()));
        }
        let secret = self
            .envelope
            .decrypt(&row.get::<String, _>("secret_ciphertext"))?;
        let spec: ProxySpec = serde_json::from_value(row.get::<serde_json::Value, _>("spec"))
            .map_err(|e| BrokerError::Internal(format!("grant spec: {e}")))?;
        let resource = row.get::<String, _>("resource");
        sqlx::query("DELETE FROM stripe_grants WHERE grant_id = $1")
            .bind(grant_id)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(RedeemedGrant {
            secret,
            spec,
            resource,
            authorization_receipt_id: row.get("authorization_receipt_id"),
            action_id: row.get("action_id"),
            agent_id: row.get("agent_id"),
        })
    }

    async fn bind(
        &self,
        tenant: &str,
        grant_id: &str,
        authorization_receipt_id: &str,
        action_id: &str,
        agent_id: &str,
    ) -> Result<bool, BrokerError> {
        let result = sqlx::query(
            "UPDATE stripe_grants
                SET authorization_receipt_id = $1, action_id = $2, agent_id = $3
              WHERE grant_id = $4 AND tenant = $5",
        )
        .bind(authorization_receipt_id)
        .bind(action_id)
        .bind(agent_id)
        .bind(grant_id)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(map)?;
        Ok(result.rows_affected() > 0)
    }

    async fn revoke(&self, tenant: &str, grant_id: &str) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query("DELETE FROM stripe_grants WHERE grant_id = $1 AND tenant = $2")
            .bind(grant_id)
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected() > 0)
    }

    async fn count(&self) -> Result<usize, BrokerError> {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM stripe_grants")
            .fetch_one(&self.pool)
            .await
            .map_err(map)?;
        Ok(count.max(0) as usize)
    }
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}

pub struct StripeIssuer {
    cfg: StripeConfig,
    grants: Arc<dyn GrantStore>,
}

impl StripeIssuer {
    pub fn new(cfg: StripeConfig) -> Self {
        Self::with_store(cfg, Arc::new(MemoryGrantStore::new(DEFAULT_MAX_GRANTS)))
    }

    pub fn with_max_grants(cfg: StripeConfig, max_grants: usize) -> Self {
        Self::with_store(cfg, Arc::new(MemoryGrantStore::new(max_grants)))
    }

    pub fn with_store(cfg: StripeConfig, grants: Arc<dyn GrantStore>) -> Self {
        Self { cfg, grants }
    }

    /// Number of grants currently held (ops/tests).
    pub async fn grant_count(&self) -> Result<usize, BrokerError> {
        self.grants.count().await
    }

    /// Map a resource to the narrowest configured restricted key.
    ///
    /// `stripe:refunds.create` -> key `refunds_create`; falls back to `default`.
    pub fn select_key(&self, resource: &str) -> Option<&str> {
        let suffix = resource
            .split_once(':')
            .map(|(_, rest)| rest)
            .unwrap_or(resource);
        let key_name = suffix.replace(['.', ':'], "_");
        self.cfg
            .restricted_keys
            .get(&key_name)
            .or_else(|| self.cfg.restricted_keys.get("default"))
            .map(|s| s.as_str())
    }

    fn spec(&self) -> ProxySpec {
        ProxySpec {
            base_url: self.cfg.api_base.clone(),
            auth_header: "authorization".to_string(),
            auth_scheme: "Bearer".to_string(),
        }
    }
}

#[async_trait]
impl Issuer for StripeIssuer {
    fn provider(&self) -> &'static str {
        "stripe"
    }

    async fn issue(&self, req: &IssueRequest) -> Result<EphemeralCredential, BrokerError> {
        let secret_key = self
            .select_key(&req.resource)
            .ok_or_else(|| {
                BrokerError::Issuer(format!(
                    "stripe: no restricted key configured for '{}'",
                    req.resource
                ))
            })?
            .to_string();

        let ttl_seconds = req.ttl_seconds.max(1);
        let grant_id = format!(
            "grant_{}_{}",
            self.provider(),
            uuid::Uuid::new_v4().simple()
        );
        let expires_at = Utc::now() + Duration::seconds(ttl_seconds as i64);

        self.grants
            .insert(
                grant_id.clone(),
                StoredGrant {
                    secret_key,
                    tenant: req.tenant.clone(),
                    resource: req.resource.clone(),
                    args_hash: req.args_hash.clone(),
                    expires_at,
                    spec: self.spec(),
                    authorization_receipt_id: None,
                    action_id: None,
                    agent_id: None,
                },
            )
            .await?;

        Ok(EphemeralCredential {
            provider: self.provider().to_string(),
            resource: req.resource.clone(),
            ttl_seconds,
            single_use: true,
            args_hash: req.args_hash.clone(),
            material: CredentialMaterial::Grant {
                grant_id,
                proxy_required: true,
            },
            reference: None,
            issuance_id: None,
        })
    }

    /// Read a grant's resource without consuming it.
    async fn peek_grant_resource(
        &self,
        tenant: &str,
        grant_id: &str,
    ) -> Result<Option<String>, BrokerError> {
        self.grants.peek(tenant, grant_id).await
    }

    /// Release a grant's secret if the tenant and arguments match and it has not expired.
    /// Single-use: the grant is consumed on success.
    async fn redeem_grant(
        &self,
        tenant: &str,
        grant_id: &str,
        args_hash: &str,
    ) -> Result<RedeemedGrant, BrokerError> {
        self.grants.redeem(tenant, grant_id, args_hash).await
    }

    async fn bind_grant(
        &self,
        tenant: &str,
        grant_id: &str,
        authorization_receipt_id: &str,
        action_id: &str,
        agent_id: &str,
    ) -> Result<bool, BrokerError> {
        self.grants
            .bind(
                tenant,
                grant_id,
                authorization_receipt_id,
                action_id,
                agent_id,
            )
            .await
    }

    /// Invalidate a broker-held grant immediately (tenant-scoped).
    async fn revoke_grant(&self, tenant: &str, grant_id: &str) -> Result<bool, BrokerError> {
        self.grants.revoke(tenant, grant_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StripeConfig {
        let mut restricted_keys = HashMap::new();
        restricted_keys.insert("refunds_create".to_string(), "rk_refunds".to_string());
        restricted_keys.insert("charges_create".to_string(), "rk_charges".to_string());
        restricted_keys.insert("default".to_string(), "rk_default".to_string());
        StripeConfig {
            restricted_keys,
            api_base: "https://api.stripe.com".into(),
        }
    }

    fn req(resource: &str, args_hash: &str) -> IssueRequest {
        IssueRequest {
            tenant: "t".into(),
            agent_id: "a".into(),
            user_id: "u".into(),
            resource: resource.into(),
            scope: vec![],
            ttl_seconds: 30,
            args_hash: args_hash.into(),
            args: serde_json::json!({}),
        }
    }

    #[test]
    fn selects_narrowest_key() {
        let issuer = StripeIssuer::new(cfg());
        assert_eq!(
            issuer.select_key("stripe:refunds.create"),
            Some("rk_refunds")
        );
        assert_eq!(
            issuer.select_key("stripe:charges.create"),
            Some("rk_charges")
        );
    }

    #[test]
    fn falls_back_to_default() {
        let issuer = StripeIssuer::new(cfg());
        assert_eq!(
            issuer.select_key("stripe:disputes.list"),
            Some("rk_default")
        );
    }

    #[tokio::test]
    async fn issue_returns_grant_and_redeems_once() {
        let issuer = StripeIssuer::new(cfg());
        let cred = issuer
            .issue(&req("stripe:refunds.create", "0xabc"))
            .await
            .unwrap();
        let grant_id = match &cred.material {
            CredentialMaterial::Grant {
                grant_id,
                proxy_required,
            } => {
                assert!(*proxy_required);
                grant_id.clone()
            }
            other => panic!("expected grant, got {other:?}"),
        };
        assert!(grant_id.starts_with("grant_stripe_"));
        let redeemed = issuer.redeem_grant("t", &grant_id, "0xabc").await.unwrap();
        assert_eq!(redeemed.secret, "rk_refunds");
        assert_eq!(redeemed.spec.base_url, "https://api.stripe.com");
        // single-use: second redemption fails
        assert!(issuer.redeem_grant("t", &grant_id, "0xabc").await.is_err());
    }

    #[tokio::test]
    async fn grants_can_be_bound_to_an_authorization() {
        let issuer = StripeIssuer::new(cfg());
        let cred = issuer
            .issue(&req("stripe:refunds.create", "0xabc"))
            .await
            .unwrap();
        let grant_id = match &cred.material {
            CredentialMaterial::Grant { grant_id, .. } => grant_id.clone(),
            _ => unreachable!(),
        };
        assert!(issuer
            .bind_grant(
                "t",
                &grant_id,
                &format!("0x{}", "aa".repeat(32)),
                "action_1",
                "a",
            )
            .await
            .unwrap());
        let redeemed = issuer.redeem_grant("t", &grant_id, "0xabc").await.unwrap();
        assert_eq!(
            redeemed.authorization_receipt_id.as_deref(),
            Some(format!("0x{}", "aa".repeat(32)).as_str())
        );
        assert_eq!(redeemed.action_id.as_deref(), Some("action_1"));
        assert_eq!(redeemed.agent_id.as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn redeem_rejects_mismatched_args() {
        let issuer = StripeIssuer::new(cfg());
        let cred = issuer
            .issue(&req("stripe:refunds.create", "0xabc"))
            .await
            .unwrap();
        let grant_id = match &cred.material {
            CredentialMaterial::Grant { grant_id, .. } => grant_id.clone(),
            _ => unreachable!(),
        };
        assert!(issuer
            .redeem_grant("t", &grant_id, "0xdifferent")
            .await
            .is_err());
        // A mismatch does not consume the grant.
        assert!(issuer.redeem_grant("t", &grant_id, "0xabc").await.is_ok());
    }

    #[tokio::test]
    async fn missing_key_errors() {
        let issuer = StripeIssuer::new(StripeConfig {
            restricted_keys: HashMap::new(),
            api_base: "https://api.stripe.com".into(),
        });
        assert!(issuer
            .issue(&req("stripe:refunds.create", "0x0"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn grant_store_is_bounded() {
        let issuer = StripeIssuer::with_max_grants(cfg(), 3);
        for _ in 0..10 {
            issuer
                .issue(&req("stripe:refunds.create", "0xa"))
                .await
                .unwrap();
        }
        assert!(
            issuer.grant_count().await.unwrap() <= 3,
            "grant store must stay bounded"
        );
    }

    #[tokio::test]
    async fn grants_are_tenant_scoped() {
        let issuer = StripeIssuer::new(cfg());
        let cred = issuer
            .issue(&req("stripe:refunds.create", "0xabc"))
            .await
            .unwrap();
        let grant_id = match &cred.material {
            CredentialMaterial::Grant { grant_id, .. } => grant_id.clone(),
            _ => unreachable!(),
        };

        // another tenant cannot redeem or revoke the grant
        assert!(issuer
            .redeem_grant("other", &grant_id, "0xabc")
            .await
            .is_err());
        assert!(!issuer.revoke_grant("other", &grant_id).await.unwrap());

        // the owner can
        assert!(issuer.revoke_grant("t", &grant_id).await.unwrap());
    }
}
