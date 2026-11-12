//! Postgres-backed anchor records and per-tenant anchor targets.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::anchoring::{
    new_claim, AnchorRecord, AnchorStore, AnchorTarget, AnchorTargetStore, ClaimOutcome,
};
use crate::error::BrokerError;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS anchors (
    id         TEXT        PRIMARY KEY,
    tenant     TEXT        NOT NULL,
    agent      TEXT        NOT NULL,
    merkle_root TEXT       NOT NULL,
    count      BIGINT      NOT NULL,
    chain_id   BIGINT      NOT NULL,
    contract   TEXT        NOT NULL,
    tx_hash    TEXT        NOT NULL,
    status     TEXT        NOT NULL,
    block_number BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS anchors_tenant_agent_idx ON anchors (tenant, agent, created_at DESC);
ALTER TABLE anchors ADD COLUMN IF NOT EXISTS block_number BIGINT;
ALTER TABLE anchors ALTER COLUMN tx_hash DROP NOT NULL;
-- Only one *live* record may hold a given root (claims prevent duplicate submissions).
CREATE UNIQUE INDEX IF NOT EXISTS anchors_active_root_key
    ON anchors (tenant, agent, merkle_root) WHERE status NOT IN ('failed', 'reorged');

CREATE TABLE IF NOT EXISTS anchor_targets (
    tenant         TEXT        PRIMARY KEY,
    chain_id       BIGINT      NOT NULL,
    rpc_url        TEXT        NOT NULL,
    contract       TEXT        NOT NULL,
    private_key    TEXT,
    signer_history JSONB       NOT NULL DEFAULT '[]'::jsonb,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE anchor_targets
    ADD COLUMN IF NOT EXISTS signer_history JSONB NOT NULL DEFAULT '[]'::jsonb;
"#;

pub struct PostgresAnchoring {
    pool: PgPool,
}

impl PostgresAnchoring {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        let pool = crate::db::connect_pool(url, 5)?;
        Ok(Self { pool })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM anchors")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        sqlx::query("DELETE FROM anchor_targets")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl AnchorStore for PostgresAnchoring {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn record(&self, record: AnchorRecord) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, &record.tenant).await?;
        sqlx::query(
            "INSERT INTO anchors (id, tenant, agent, merkle_root, count, chain_id, contract, tx_hash, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())",
        )
        .bind(&record.id)
        .bind(&record.tenant)
        .bind(&record.agent)
        .bind(&record.merkle_root)
        .bind(record.count as i64)
        .bind(record.chain_id as i64)
        .bind(&record.contract)
        .bind(record.tx_hash.as_deref())
        .bind(&record.status)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<AnchorRecord>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query("SELECT * FROM anchors WHERE tenant = $1 ORDER BY created_at DESC")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await
            .map_err(map)?;
        Ok(rows.into_iter().map(decode_record).collect())
    }

    async fn latest(&self, tenant: &str, agent: &str) -> Result<Option<AnchorRecord>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT * FROM anchors WHERE tenant = $1 AND agent = $2 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant)
        .bind(agent)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        Ok(row.map(decode_record))
    }

    async fn pending(&self, tenant: &str) -> Result<Vec<AnchorRecord>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT * FROM anchors WHERE tenant = $1 AND status <> 'finalized' ORDER BY created_at ASC",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        Ok(rows.into_iter().map(decode_record).collect())
    }

    async fn prune_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        let result = sqlx::query(
            "DELETE FROM anchors
              WHERE created_at < $1 AND status IN ('finalized', 'failed', 'reorged')",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(map)?;
        Ok(result.rows_affected())
    }

    async fn claim(
        &self,
        tenant: &str,
        agent: &str,
        merkle_root: &str,
        count: u64,
        chain_id: u64,
        contract: &str,
    ) -> Result<ClaimOutcome, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let candidate = new_claim(tenant, agent, merkle_root, count, chain_id, contract);
        let result = sqlx::query(
            "INSERT INTO anchors (id, tenant, agent, merkle_root, count, chain_id, contract, tx_hash, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, 'claimed')
             ON CONFLICT (tenant, agent, merkle_root) WHERE status NOT IN ('failed', 'reorged') DO NOTHING",
        )
        .bind(&candidate.id)
        .bind(tenant)
        .bind(agent)
        .bind(merkle_root)
        .bind(count as i64)
        .bind(chain_id as i64)
        .bind(contract)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;

        if result.rows_affected() == 1 {
            Ok(ClaimOutcome::Claimed { id: candidate.id })
        } else {
            Ok(ClaimOutcome::AlreadyClaimed)
        }
    }

    async fn settle(
        &self,
        tenant: &str,
        id: &str,
        tx_hash: &str,
        status: &str,
        block_number: Option<u64>,
    ) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "UPDATE anchors SET tx_hash = $3, status = $4, block_number = $5
              WHERE id = $1 AND tenant = $2",
        )
        .bind(id)
        .bind(tenant)
        .bind(tx_hash)
        .bind(status)
        .bind(block_number.map(|n| n as i64))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn update(
        &self,
        tenant: &str,
        id: &str,
        status: &str,
        block_number: Option<u64>,
    ) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "UPDATE anchors SET status = $2, block_number = $3 WHERE id = $1 AND tenant = $4",
        )
        .bind(id)
        .bind(status)
        .bind(block_number.map(|n| n as i64))
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl AnchorTargetStore for PostgresAnchoring {
    async fn set(&self, tenant: &str, target: AnchorTarget) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "INSERT INTO anchor_targets
                 (tenant, chain_id, rpc_url, contract, private_key, signer_history, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, now())
             ON CONFLICT (tenant) DO UPDATE SET
                 chain_id = EXCLUDED.chain_id,
                 rpc_url = EXCLUDED.rpc_url,
                 contract = EXCLUDED.contract,
                 private_key = EXCLUDED.private_key,
                 signer_history = EXCLUDED.signer_history,
                 updated_at = now()",
        )
        .bind(tenant)
        .bind(target.chain_id as i64)
        .bind(&target.rpc_url)
        .bind(&target.contract)
        .bind(&target.private_key)
        .bind(sqlx::types::Json(&target.signer_history))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn get(&self, tenant: &str) -> Result<Option<AnchorTarget>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query("SELECT * FROM anchor_targets WHERE tenant = $1")
            .bind(tenant)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
        Ok(row.map(decode_target))
    }

    async fn list(&self) -> Result<Vec<(String, AnchorTarget)>, BrokerError> {
        let rows = sqlx::query("SELECT * FROM anchor_targets ORDER BY tenant")
            .fetch_all(&self.pool)
            .await
            .map_err(map)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let tenant = r.get::<String, _>("tenant");
                (tenant, decode_target(r))
            })
            .collect())
    }
}

fn decode_record(row: sqlx::postgres::PgRow) -> AnchorRecord {
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    AnchorRecord {
        id: row.get("id"),
        tenant: row.get("tenant"),
        agent: row.get("agent"),
        merkle_root: row.get("merkle_root"),
        count: row.get::<i64, _>("count") as u64,
        chain_id: row.get::<i64, _>("chain_id") as u64,
        contract: row.get("contract"),
        tx_hash: row.get::<Option<String>, _>("tx_hash"),
        status: row.get("status"),
        block_number: row.get::<Option<i64>, _>("block_number").map(|n| n as u64),
        created_at: created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

fn decode_target(row: sqlx::postgres::PgRow) -> AnchorTarget {
    let history: sqlx::types::Json<Vec<String>> = row.get("signer_history");
    AnchorTarget {
        chain_id: row.get::<i64, _>("chain_id") as u64,
        rpc_url: row.get("rpc_url"),
        contract: row.get("contract"),
        private_key: row.get("private_key"),
        signer_history: history.0,
    }
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
