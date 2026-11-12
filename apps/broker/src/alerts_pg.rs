//! Postgres-backed per-tenant alert routing.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::alerts::{AlertTarget, AlertTargetStore};
use crate::error::BrokerError;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS alert_targets (
    tenant         TEXT        PRIMARY KEY,
    url            TEXT        NOT NULL,
    token          TEXT,
    events         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    auto_ack_below BIGINT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE alert_targets ADD COLUMN IF NOT EXISTS auto_ack_below BIGINT;
"#;

pub struct PostgresAlertTargets {
    pool: PgPool,
}

impl PostgresAlertTargets {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            pool: crate::db::connect_pool(url, 3)?,
        })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM alert_targets")
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
impl AlertTargetStore for PostgresAlertTargets {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn set(&self, tenant: &str, target: AlertTarget) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "INSERT INTO alert_targets (tenant, url, token, events, auto_ack_below, updated_at)
             VALUES ($1, $2, $3, $4, $5, now())
             ON CONFLICT (tenant) DO UPDATE SET
                 url = EXCLUDED.url,
                 token = EXCLUDED.token,
                 events = EXCLUDED.events,
                 auto_ack_below = EXCLUDED.auto_ack_below,
                 updated_at = now()",
        )
        .bind(tenant)
        .bind(&target.url)
        .bind(&target.token)
        .bind(sqlx::types::Json(&target.events))
        .bind(target.auto_ack_below.map(|value| value as i64))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn get(&self, tenant: &str) -> Result<Option<AlertTarget>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT url, token, events, auto_ack_below FROM alert_targets WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let events: sqlx::types::Json<Vec<String>> = row.get("events");
        Ok(Some(AlertTarget {
            url: row.get("url"),
            token: row.get("token"),
            events: events.0,
            auto_ack_below: row
                .get::<Option<i64>, _>("auto_ack_below")
                .and_then(|value| u64::try_from(value).ok()),
        }))
    }

    async fn delete(&self, tenant: &str) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query("DELETE FROM alert_targets WHERE tenant = $1")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected() > 0)
    }
}
