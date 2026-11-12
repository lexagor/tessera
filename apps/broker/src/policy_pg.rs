//! Postgres-backed policy store.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::error::BrokerError;
use crate::policy::{Policy, PolicyStore, PolicyVersion};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS policies (
    tenant     TEXT        NOT NULL,
    id         TEXT        NOT NULL,
    version    INTEGER     NOT NULL,
    name       TEXT        NOT NULL,
    document   JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);
CREATE TABLE IF NOT EXISTS policy_versions (
    tenant       TEXT        NOT NULL,
    id           TEXT        NOT NULL,
    version      INTEGER     NOT NULL,
    content_hash TEXT        NOT NULL,
    document     JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id, version)
);
"#;

pub struct PostgresPolicyStore {
    pool: PgPool,
}

impl PostgresPolicyStore {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        let pool = crate::db::connect_pool(url, 5)?;
        Ok(Self { pool })
    }

    /// Remove all rows (test helper).
    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM policies")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        sqlx::query("DELETE FROM policy_versions")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl PolicyStore for PostgresPolicyStore {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn policies_for(&self, tenant: &str) -> Result<Vec<Policy>, BrokerError> {
        self.list(tenant).await
    }

    async fn list(&self, tenant: &str) -> Result<Vec<Policy>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query("SELECT document FROM policies WHERE tenant = $1 ORDER BY id")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await
            .map_err(map)?;
        rows.into_iter().map(decode_policy).collect()
    }

    async fn get(&self, tenant: &str, id: &str) -> Result<Option<Policy>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query("SELECT document FROM policies WHERE tenant = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
        row.map(decode_policy).transpose()
    }

    async fn upsert(&self, tenant: &str, policy: Policy) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let value = serde_json::to_value(&policy)
            .map_err(|e| BrokerError::Internal(format!("serialize policy: {e}")))?;
        let content_hash = policy.content_hash();
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT content_hash FROM policy_versions WHERE tenant = $1 AND id = $2 AND version = $3",
        )
        .bind(tenant)
        .bind(&policy.id)
        .bind(policy.version as i32)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        if let Some(existing) = existing {
            if existing != content_hash {
                return Err(BrokerError::Invalid(format!(
                    "policy '{}' version {} already exists with different content; increment the version",
                    policy.id, policy.version
                )));
            }
        }
        let document = sqlx::types::Json(value.clone());
        sqlx::query(
            "INSERT INTO policies (tenant, id, version, name, document, updated_at)
             VALUES ($1, $2, $3, $4, $5, now())
             ON CONFLICT (tenant, id) DO UPDATE SET
                 version = EXCLUDED.version,
                 name = EXCLUDED.name,
                 document = EXCLUDED.document,
                 updated_at = now()",
        )
        .bind(tenant)
        .bind(&policy.id)
        .bind(policy.version as i32)
        .bind(&policy.name)
        .bind(document)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        // Append-only history: v2 receipts bind `policy.content_hash()`, so an old receipt
        // must remain checkable after the active policy is edited.
        sqlx::query(
            "INSERT INTO policy_versions (tenant, id, version, content_hash, document)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant, id, version) DO NOTHING",
        )
        .bind(tenant)
        .bind(&policy.id)
        .bind(policy.version as i32)
        .bind(content_hash)
        .bind(sqlx::types::Json(value))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn versions(&self, tenant: &str) -> Result<Vec<PolicyVersion>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT id, version, content_hash, document
               FROM policy_versions WHERE tenant = $1 ORDER BY id, version",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(PolicyVersion {
                id: row.get::<String, _>("id"),
                version: row.get::<i32, _>("version").max(0) as u32,
                content_hash: row.get::<String, _>("content_hash"),
                document: row.get::<serde_json::Value, _>("document"),
            });
        }
        Ok(out)
    }

    async fn delete(&self, tenant: &str, id: &str) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query("DELETE FROM policies WHERE tenant = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected() > 0)
    }
}

fn decode_policy(row: sqlx::postgres::PgRow) -> Result<Policy, BrokerError> {
    let value = row.get::<serde_json::Value, _>("document");
    serde_json::from_value(value)
        .map_err(|e| BrokerError::Internal(format!("deserialize policy: {e}")))
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
