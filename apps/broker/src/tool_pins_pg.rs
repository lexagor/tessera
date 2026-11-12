//! Postgres-backed tool-definition pins.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::error::BrokerError;
use crate::tool_pins::{ToolPin, ToolPinStore};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS tool_pins (
    tenant           TEXT        NOT NULL,
    tool             TEXT        NOT NULL,
    definition_hash  TEXT        NOT NULL,
    definition       JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, tool)
);
"#;

pub struct PostgresToolPins {
    pool: PgPool,
}

impl PostgresToolPins {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            pool: crate::db::connect_pool(url, 3)?,
        })
    }
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}

#[async_trait]
impl ToolPinStore for PostgresToolPins {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn set(&self, pin: ToolPin) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, &pin.tenant).await?;
        sqlx::query(
            "INSERT INTO tool_pins (tenant, tool, definition_hash, definition, created_at, updated_at)
             VALUES ($1, $2, $3, $4, now(), now())
             ON CONFLICT (tenant, tool) DO UPDATE SET
                 definition_hash = EXCLUDED.definition_hash,
                 definition = EXCLUDED.definition,
                 updated_at = now()",
        )
        .bind(&pin.tenant)
        .bind(&pin.tool)
        .bind(&pin.definition_hash)
        .bind(sqlx::types::Json(&pin.definition))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn get(&self, tenant: &str, tool: &str) -> Result<Option<ToolPin>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query("SELECT * FROM tool_pins WHERE tenant = $1 AND tool = $2")
            .bind(tenant)
            .bind(tool)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        row.map(decode).transpose()
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ToolPin>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query("SELECT * FROM tool_pins WHERE tenant = $1 ORDER BY tool ASC")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        rows.into_iter().map(decode).collect()
    }

    async fn delete(&self, tenant: &str, tool: &str) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query("DELETE FROM tool_pins WHERE tenant = $1 AND tool = $2")
            .bind(tenant)
            .bind(tool)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected() > 0)
    }
}

fn decode(row: sqlx::postgres::PgRow) -> Result<ToolPin, BrokerError> {
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    let definition: sqlx::types::Json<serde_json::Value> = row.get("definition");
    Ok(ToolPin {
        tenant: row.get("tenant"),
        tool: row.get("tool"),
        definition_hash: row.get("definition_hash"),
        definition: definition.0,
        created_at: created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        updated_at: updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}
