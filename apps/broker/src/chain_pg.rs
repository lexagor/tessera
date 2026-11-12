//! Postgres-backed receipt chain, scoped to `(tenant, agent)`.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::chain::{AppendOutcome, ChainEntry, ChainStore};
use crate::error::BrokerError;
use crate::receipt::GrantReceipt;

const BASE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS receipt_chain (
    id          BIGSERIAL,
    tenant      TEXT        NOT NULL,
    agent       TEXT        NOT NULL,
    seq         BIGINT      NOT NULL,
    payload_hash TEXT       NOT NULL,
    prev_hash   TEXT,
    authorization_receipt_id TEXT,
    receipt     JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant, agent, seq),
    UNIQUE (tenant, agent, payload_hash)
) PARTITION BY HASH (agent);
"#;

/// Eight hash partitions on `agent`. Hashing on the partition key lets the unique
/// constraints on `(tenant, agent, …)` hold, and confines each agent's chain (and its
/// advisory-lock contention) to a single partition.
const PARTITIONS_DDL: &str = r#"
CREATE INDEX IF NOT EXISTS receipt_chain_prev_idx
    ON receipt_chain (tenant, agent, prev_hash);
CREATE TABLE IF NOT EXISTS receipt_chain_p0 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE IF NOT EXISTS receipt_chain_p1 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE IF NOT EXISTS receipt_chain_p2 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE IF NOT EXISTS receipt_chain_p3 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE IF NOT EXISTS receipt_chain_p4 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE IF NOT EXISTS receipt_chain_p5 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE IF NOT EXISTS receipt_chain_p6 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE IF NOT EXISTS receipt_chain_p7 PARTITION OF receipt_chain FOR VALUES WITH (MODULUS 8, REMAINDER 7);
"#;

/// Re-scope uniqueness from `(agent, …)` to `(tenant, agent, …)` and enforce the chain link
/// (no two entries may share a `prev`), which makes forks impossible at the storage layer.
const CONSTRAINTS_DDL: &str = r#"
ALTER TABLE receipt_chain DROP CONSTRAINT IF EXISTS receipt_chain_agent_seq_key;
ALTER TABLE receipt_chain DROP CONSTRAINT IF EXISTS receipt_chain_agent_payload_hash_key;
ALTER TABLE receipt_chain DROP CONSTRAINT IF EXISTS receipt_chain_tenant_agent_seq_key;
ALTER TABLE receipt_chain DROP CONSTRAINT IF EXISTS receipt_chain_tenant_agent_payload_hash_key;
ALTER TABLE receipt_chain ADD CONSTRAINT receipt_chain_tenant_agent_seq_key UNIQUE (tenant, agent, seq);
ALTER TABLE receipt_chain ADD CONSTRAINT receipt_chain_tenant_agent_payload_hash_key UNIQUE (tenant, agent, payload_hash);
CREATE UNIQUE INDEX IF NOT EXISTS receipt_chain_link_key
    ON receipt_chain (tenant, agent, prev_hash) WHERE prev_hash IS NOT NULL;
ALTER TABLE receipt_chain ADD COLUMN IF NOT EXISTS authorization_receipt_id TEXT;
CREATE INDEX IF NOT EXISTS receipt_chain_authorization_idx
    ON receipt_chain (tenant, agent, authorization_receipt_id)
    WHERE authorization_receipt_id IS NOT NULL;
"#;

pub struct PostgresChainStore {
    pool: PgPool,
}

impl PostgresChainStore {
    /// Create a lazily-connecting pool. Call [`ChainStore::migrate`] before first use.
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        let pool = crate::db::connect_pool(url, 10)?;
        Ok(Self { pool })
    }

    /// Remove all rows (test helper).
    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM receipt_chain")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }

    /// Drop and recreate the table (test helper; exercises the partitioning migration).
    pub async fn reset(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql("DROP TABLE IF EXISTS receipt_chain CASCADE")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        self.migrate().await
    }

    /// Whether `receipt_chain` is a partitioned table.
    pub async fn is_partitioned(&self) -> Result<bool, BrokerError> {
        let relkind: Option<String> = sqlx::query_scalar(
            "SELECT c.relkind::text
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relname = 'receipt_chain' AND n.nspname = current_schema()",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map)?;
        Ok(relkind.as_deref() == Some("p"))
    }
}

#[async_trait]
impl ChainStore for PostgresChainStore {
    async fn migrate(&self) -> Result<(), BrokerError> {
        let relkind: Option<String> = sqlx::query_scalar(
            "SELECT c.relkind::text
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relname = 'receipt_chain' AND n.nspname = current_schema()",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map)?;

        match relkind.as_deref() {
            Some("p") => {
                sqlx::raw_sql(PARTITIONS_DDL)
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
            }
            Some(_) => {
                sqlx::raw_sql("ALTER TABLE receipt_chain RENAME TO receipt_chain_legacy")
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
                sqlx::raw_sql(BASE_DDL)
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
                sqlx::raw_sql(PARTITIONS_DDL)
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
                sqlx::raw_sql(
                    "INSERT INTO receipt_chain (tenant, agent, seq, payload_hash, prev_hash, receipt, created_at)
                     SELECT tenant, agent, seq, payload_hash, prev_hash, receipt, created_at
                       FROM receipt_chain_legacy",
                )
                .execute(&self.pool)
                .await
                .map_err(map)?;
                sqlx::raw_sql("DROP TABLE receipt_chain_legacy")
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
            }
            None => {
                sqlx::raw_sql(BASE_DDL)
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
                sqlx::raw_sql(PARTITIONS_DDL)
                    .execute(&self.pool)
                    .await
                    .map_err(map)?;
            }
        }

        sqlx::raw_sql(CONSTRAINTS_DDL)
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }

    async fn head_hash(&self, tenant: &str, agent: &str) -> Result<Option<String>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT payload_hash FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 ORDER BY seq DESC LIMIT 1",
        )
        .bind(tenant)
        .bind(agent)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        Ok(row.map(|r| r.get::<String, _>("payload_hash")))
    }

    async fn append(
        &self,
        tenant: &str,
        agent: &str,
        entry: ChainEntry,
    ) -> Result<AppendOutcome, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;

        // Serialize appends per (tenant, agent).
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2)::bigint)")
            .bind(tenant)
            .bind(agent)
            .execute(&mut *tx)
            .await
            .map_err(map)?;

        let head = sqlx::query(
            "SELECT payload_hash, seq FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 ORDER BY seq DESC LIMIT 1",
        )
        .bind(tenant)
        .bind(agent)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;

        let (current_head, next_seq) = match head {
            Some(row) => (
                Some(row.get::<String, _>("payload_hash")),
                row.get::<i64, _>("seq") + 1,
            ),
            None => (None, 0),
        };

        if current_head != entry.receipt.prev {
            tx.rollback().await.ok();
            return Ok(AppendOutcome::Conflict);
        }

        let receipt = sqlx::types::Json(
            serde_json::to_value(&entry.receipt)
                .map_err(|e| BrokerError::Internal(format!("serialize receipt: {e}")))?,
        );

        let result = sqlx::query(
            "INSERT INTO receipt_chain
                (tenant, agent, seq, payload_hash, prev_hash, authorization_receipt_id, receipt)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant)
        .bind(agent)
        .bind(next_seq)
        .bind(&entry.payload_hash)
        .bind(entry.receipt.prev.as_deref())
        .bind(entry.receipt.authorization_receipt_id.as_deref())
        .bind(receipt)
        .execute(&mut *tx)
        .await;

        match result {
            Ok(_) => {
                tx.commit().await.map_err(map)?;
                Ok(AppendOutcome::Appended)
            }
            // Unique-violation (e.g. the same `prev` link inserted concurrently) is a
            // conflict: the caller re-reads the head and retries.
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
                tx.rollback().await.ok();
                Ok(AppendOutcome::Conflict)
            }
            Err(e) => Err(map(e)),
        }
    }

    async fn find_outcome(
        &self,
        tenant: &str,
        agent: &str,
        prev_hash: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        // Outcomes carry a result hash; plain successor authorizations do not.
        let row = sqlx::query(
            "SELECT payload_hash, receipt FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 AND prev_hash = $3
                AND (receipt -> 'call' ->> 'resultHash') IS NOT NULL
              LIMIT 1",
        )
        .bind(tenant)
        .bind(agent)
        .bind(prev_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        match row {
            Some(row) => {
                let receipt: sqlx::types::Json<GrantReceipt> = row.get("receipt");
                Ok(Some(ChainEntry {
                    payload_hash: row.get("payload_hash"),
                    receipt: receipt.0,
                }))
            }
            None => Ok(None),
        }
    }

    async fn find_outcome_for_authorization(
        &self,
        tenant: &str,
        agent: &str,
        authorization_receipt_id: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT payload_hash, receipt FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 AND authorization_receipt_id = $3
                AND (receipt -> 'call' ->> 'resultHash') IS NOT NULL
              LIMIT 1",
        )
        .bind(tenant)
        .bind(agent)
        .bind(authorization_receipt_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        if row.is_none() {
            let row = sqlx::query(
                "SELECT payload_hash, receipt FROM receipt_chain
                  WHERE tenant = $1 AND agent = $2 AND prev_hash = $3
                    AND (receipt -> 'call' ->> 'resultHash') IS NOT NULL
                    AND (receipt ->> 'authorizationReceiptId') IS NULL
                  LIMIT 1",
            )
            .bind(tenant)
            .bind(agent)
            .bind(authorization_receipt_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
            tx.commit().await.map_err(map)?;
            return row.map(decode_entry).transpose();
        }
        tx.commit().await.map_err(map)?;
        row.map(decode_entry).transpose()
    }

    async fn find_by_prev(
        &self,
        tenant: &str,
        agent: &str,
        prev_hash: &str,
    ) -> Result<Option<ChainEntry>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT payload_hash, receipt FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 AND prev_hash = $3
              LIMIT 1",
        )
        .bind(tenant)
        .bind(agent)
        .bind(prev_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        match row {
            Some(row) => {
                let receipt: sqlx::types::Json<GrantReceipt> = row.get("receipt");
                Ok(Some(ChainEntry {
                    payload_hash: row.get("payload_hash"),
                    receipt: receipt.0,
                }))
            }
            None => Ok(None),
        }
    }

    async fn find(
        &self,
        tenant: &str,
        agent: &str,
        payload_hash: &str,
    ) -> Result<Option<GrantReceipt>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT receipt FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 AND payload_hash = $3",
        )
        .bind(tenant)
        .bind(agent)
        .bind(payload_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        row.map(decode_receipt).transpose()
    }

    async fn chain(&self, tenant: &str, agent: &str) -> Result<Vec<ChainEntry>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT payload_hash, receipt FROM receipt_chain
              WHERE tenant = $1 AND agent = $2 ORDER BY seq ASC",
        )
        .bind(tenant)
        .bind(agent)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        rows.into_iter()
            .map(|row| {
                let payload_hash = row.get::<String, _>("payload_hash");
                let receipt = decode_receipt(row)?;
                Ok(ChainEntry {
                    payload_hash,
                    receipt,
                })
            })
            .collect()
    }

    async fn len(&self, tenant: &str, agent: &str) -> Result<usize, BrokerError> {
        let row =
            sqlx::query("SELECT COUNT(*) AS n FROM receipt_chain WHERE tenant = $1 AND agent = $2")
                .bind(tenant)
                .bind(agent)
                .fetch_one(&self.pool)
                .await
                .map_err(map)?;
        Ok(row.get::<i64, _>("n") as usize)
    }

    async fn tenants(&self) -> Result<Vec<String>, BrokerError> {
        let rows = sqlx::query("SELECT DISTINCT tenant FROM receipt_chain ORDER BY tenant")
            .fetch_all(&self.pool)
            .await
            .map_err(map)?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("tenant"))
            .collect())
    }

    async fn agents_for_tenant(&self, tenant: &str) -> Result<Vec<String>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query(
            "SELECT DISTINCT agent FROM receipt_chain WHERE tenant = $1 ORDER BY agent",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("agent"))
            .collect())
    }

    async fn prune_idle_agents(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        let result = sqlx::query(
            "DELETE FROM receipt_chain
              WHERE (tenant, agent) IN (
                    SELECT tenant, agent FROM receipt_chain
                     GROUP BY tenant, agent
                    HAVING max(created_at) < $1
              )",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(map)?;
        Ok(result.rows_affected())
    }
}

fn decode_entry(row: sqlx::postgres::PgRow) -> Result<ChainEntry, BrokerError> {
    let payload_hash = row.get::<String, _>("payload_hash");
    let receipt = decode_receipt(row)?;
    Ok(ChainEntry {
        payload_hash,
        receipt,
    })
}

fn decode_receipt(row: sqlx::postgres::PgRow) -> Result<GrantReceipt, BrokerError> {
    let value = row.get::<serde_json::Value, _>("receipt");
    serde_json::from_value(value)
        .map_err(|e| BrokerError::Internal(format!("deserialize receipt: {e}")))
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
