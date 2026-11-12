//! Postgres-backed chain checkpoints.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::chain_checkpoints::{ChainCheckpoint, ChainCheckpointStore};
use crate::error::BrokerError;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS chain_checkpoints (
    tenant   TEXT        NOT NULL,
    agent    TEXT        NOT NULL,
    head     TEXT,
    count    BIGINT      NOT NULL,
    taken_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, agent)
);
"#;

pub struct PostgresChainCheckpoints {
    pool: PgPool,
}

impl PostgresChainCheckpoints {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            pool: crate::db::connect_pool(url, 3)?,
        })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM chain_checkpoints")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}

#[async_trait]
impl ChainCheckpointStore for PostgresChainCheckpoints {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn set(&self, tenant: &str, checkpoint: ChainCheckpoint) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "INSERT INTO chain_checkpoints (tenant, agent, head, count, taken_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tenant, agent) DO UPDATE SET
                 head = EXCLUDED.head,
                 count = EXCLUDED.count,
                 taken_at = now()",
        )
        .bind(tenant)
        .bind(&checkpoint.agent)
        .bind(&checkpoint.head)
        .bind(checkpoint.count as i64)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ChainCheckpoint>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT agent, head, count, taken_at FROM chain_checkpoints
              WHERE tenant = $1 ORDER BY agent ASC",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let taken_at: chrono::DateTime<chrono::Utc> = row.get("taken_at");
                ChainCheckpoint {
                    agent: row.get("agent"),
                    head: row.get("head"),
                    count: row.get::<i64, _>("count").max(0) as u64,
                    taken_at: taken_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                }
            })
            .collect())
    }
}
