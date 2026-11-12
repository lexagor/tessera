//! Postgres-backed alert acknowledgements.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::alert_acks::{AlertAck, AlertAckStore};
use crate::error::BrokerError;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS alert_acks (
    tenant     TEXT        NOT NULL,
    event      TEXT        NOT NULL,
    dedup_key  TEXT        NOT NULL,
    value      BIGINT      NOT NULL,
    acked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, event, dedup_key)
);
"#;

pub struct PostgresAlertAcks {
    pool: PgPool,
}

impl PostgresAlertAcks {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            pool: crate::db::connect_pool(url, 3)?,
        })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM alert_acks")
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
impl AlertAckStore for PostgresAlertAcks {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn set(&self, tenant: &str, ack: AlertAck) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "INSERT INTO alert_acks (tenant, event, dedup_key, value, acked_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tenant, event, dedup_key) DO UPDATE SET
                 value = EXCLUDED.value,
                 acked_at = now()",
        )
        .bind(tenant)
        .bind(&ack.event)
        .bind(&ack.dedup_key)
        .bind(ack.value as i64)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
    ) -> Result<Option<AlertAck>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT value, acked_at FROM alert_acks
              WHERE tenant = $1 AND event = $2 AND dedup_key = $3",
        )
        .bind(tenant)
        .bind(event)
        .bind(dedup_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let acked_at: chrono::DateTime<chrono::Utc> = row.get("acked_at");
        Ok(Some(AlertAck {
            event: event.to_string(),
            dedup_key: dedup_key.to_string(),
            value: row.get::<i64, _>("value").max(0) as u64,
            acked_at: acked_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }))
    }

    async fn delete(
        &self,
        tenant: &str,
        event: &str,
        dedup_key: &str,
    ) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query(
            "DELETE FROM alert_acks WHERE tenant = $1 AND event = $2 AND dedup_key = $3",
        )
        .bind(tenant)
        .bind(event)
        .bind(dedup_key)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected() > 0)
    }

    async fn retain(&self, tenant: &str, event: &str, keep: &[String]) -> Result<u64, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query(
            "DELETE FROM alert_acks
              WHERE tenant = $1 AND event = $2 AND NOT (dedup_key = ANY($3))",
        )
        .bind(tenant)
        .bind(event)
        .bind(keep)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<AlertAck>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT event, dedup_key, value, acked_at FROM alert_acks
              WHERE tenant = $1 ORDER BY acked_at DESC",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let acked_at: chrono::DateTime<chrono::Utc> = row.get("acked_at");
                AlertAck {
                    event: row.get("event"),
                    dedup_key: row.get("dedup_key"),
                    value: row.get::<i64, _>("value").max(0) as u64,
                    acked_at: acked_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                }
            })
            .collect())
    }
}
