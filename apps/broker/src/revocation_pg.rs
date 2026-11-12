//! Postgres-backed revocation registry.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::error::BrokerError;
use crate::revocation::{new_event, RevocationEvent, RevocationStore};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS revocations (
    id         TEXT        PRIMARY KEY,
    tenant     TEXT        NOT NULL,
    target     TEXT        NOT NULL,
    kind       TEXT        NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant, target)
);
"#;

pub struct PostgresRevocationStore {
    pool: PgPool,
}

impl PostgresRevocationStore {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        let pool = crate::db::connect_pool(url, 5)?;
        Ok(Self { pool })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM revocations")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl RevocationStore for PostgresRevocationStore {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn revoke(
        &self,
        tenant: &str,
        target: &str,
        kind: &str,
        reason: Option<String>,
    ) -> Result<RevocationEvent, BrokerError> {
        let candidate = new_event(tenant, target, kind, reason);
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "INSERT INTO revocations (id, tenant, target, kind, reason, created_at)
             VALUES ($1, $2, $3, $4, $5, now())
             ON CONFLICT (tenant, target) DO UPDATE SET
                 id = EXCLUDED.id,
                 kind = EXCLUDED.kind,
                 reason = EXCLUDED.reason,
                 created_at = now()",
        )
        .bind(&candidate.id)
        .bind(tenant)
        .bind(target)
        .bind(kind)
        .bind(&candidate.reason)
        .execute(&mut *tx)
        .await
        .map_err(map)?;

        let row = sqlx::query("SELECT * FROM revocations WHERE tenant = $1 AND target = $2")
            .bind(tenant)
            .bind(target)
            .fetch_one(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        decode(row)
    }

    async fn is_revoked(&self, tenant: &str, target: &str) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query("SELECT 1 FROM revocations WHERE tenant = $1 AND target = $2")
            .bind(tenant)
            .bind(target)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
        Ok(row.is_some())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<RevocationEvent>, BrokerError> {
        let rows =
            sqlx::query("SELECT * FROM revocations WHERE tenant = $1 ORDER BY created_at DESC")
                .bind(tenant)
                .fetch_all(&self.pool)
                .await
                .map_err(map)?;
        rows.into_iter().map(decode).collect()
    }
}

fn decode(row: sqlx::postgres::PgRow) -> Result<RevocationEvent, BrokerError> {
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    Ok(RevocationEvent {
        id: row.get("id"),
        tenant: row.get("tenant"),
        target: row.get("target"),
        kind: row.get("kind"),
        reason: row.get("reason"),
        created_at: created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
