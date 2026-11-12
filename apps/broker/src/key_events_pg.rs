//! Postgres-backed key-event ledger (append-only).

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::error::BrokerError;
use crate::key_events::{KeyEvent, KeyEventStore};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS key_events (
    id         TEXT        PRIMARY KEY,
    tenant     TEXT        NOT NULL,
    kind       TEXT        NOT NULL,
    key_id     TEXT        NOT NULL,
    key_name   TEXT        NOT NULL,
    prefix     TEXT        NOT NULL,
    details    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    at         TIMESTAMPTZ NOT NULL,
    prev_hash  TEXT,
    event_hash TEXT        NOT NULL,
    signature  TEXT,
    seq        BIGSERIAL
);
CREATE INDEX IF NOT EXISTS key_events_tenant_idx ON key_events (tenant, seq);
"#;

pub struct PostgresKeyEvents {
    pool: PgPool,
}

impl PostgresKeyEvents {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            pool: crate::db::connect_pool(url, 3)?,
        })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM key_events")
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
impl KeyEventStore for PostgresKeyEvents {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn append(&self, event: KeyEvent) -> Result<(), BrokerError> {
        let at = chrono::DateTime::parse_from_rfc3339(&event.at)
            .map(|ts| ts.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        let mut tx = crate::db::tenant_tx(&self.pool, &event.tenant).await?;
        sqlx::query(
            "INSERT INTO key_events
                 (id, tenant, kind, key_id, key_name, prefix, details, at, prev_hash, event_hash, signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&event.id)
        .bind(&event.tenant)
        .bind(&event.kind)
        .bind(&event.key_id)
        .bind(&event.key_name)
        .bind(&event.prefix)
        .bind(sqlx::types::Json(&event.details))
        .bind(at)
        .bind(&event.prev_hash)
        .bind(&event.event_hash)
        .bind(&event.signature)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn compact(
        &self,
        tenant: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
        mut checkpoint: KeyEvent,
    ) -> Result<Option<(usize, crate::key_events::KeyEvent)>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT id, event_hash FROM key_events
              WHERE tenant = $1 AND at < $2 ORDER BY seq ASC",
        )
        .bind(tenant)
        .bind(cutoff)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        if rows.is_empty() {
            tx.commit().await.map_err(map)?;
            return Ok(None);
        }
        let removed = rows.len();
        let through_hash: String = rows
            .last()
            .map(|row| row.get("event_hash"))
            .unwrap_or_default();
        checkpoint.prev_hash = Some(through_hash);
        let digest = crate::key_events::event_digest(&checkpoint)?;
        checkpoint.event_hash = format!("0x{}", hex::encode(digest));
        let at = chrono::DateTime::parse_from_rfc3339(&checkpoint.at)
            .map(|ts| ts.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        sqlx::query(
            "INSERT INTO key_events
                 (id, tenant, kind, key_id, key_name, prefix, details, at, prev_hash, event_hash, signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&checkpoint.id)
        .bind(&checkpoint.tenant)
        .bind(&checkpoint.kind)
        .bind(&checkpoint.key_id)
        .bind(&checkpoint.key_name)
        .bind(&checkpoint.prefix)
        .bind(sqlx::types::Json(&checkpoint.details))
        .bind(at)
        .bind(&checkpoint.prev_hash)
        .bind(&checkpoint.event_hash)
        .bind(&checkpoint.signature)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        let ids: Vec<String> = rows.iter().map(|row| row.get::<String, _>("id")).collect();
        sqlx::query("DELETE FROM key_events WHERE tenant = $1 AND id = ANY($2)")
            .bind(tenant)
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(Some((removed, checkpoint)))
    }

    async fn list(&self, tenant: &str) -> Result<Vec<KeyEvent>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query("SELECT * FROM key_events WHERE tenant = $1 ORDER BY seq ASC")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let at: chrono::DateTime<chrono::Utc> = row.get("at");
                let details: sqlx::types::Json<serde_json::Value> = row.get("details");
                KeyEvent {
                    id: row.get("id"),
                    tenant: row.get("tenant"),
                    kind: row.get("kind"),
                    key_id: row.get("key_id"),
                    key_name: row.get("key_name"),
                    prefix: row.get("prefix"),
                    details: details.0,
                    at: at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    prev_hash: row.get("prev_hash"),
                    event_hash: row.get("event_hash"),
                    signature: row.get("signature"),
                }
            })
            .collect())
    }
}
