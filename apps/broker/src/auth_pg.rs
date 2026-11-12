//! Postgres-backed API key store.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::auth::{hash_key, new_record, ApiKeyRecord, ApiKeyStore};
use crate::error::BrokerError;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS api_keys (
    id                 TEXT        PRIMARY KEY,
    tenant             TEXT        NOT NULL,
    name               TEXT        NOT NULL,
    key_hash           TEXT        NOT NULL UNIQUE,
    prefix             TEXT        NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ,
    rate_limit_per_min INTEGER,
    scope              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    expires_at         TIMESTAMPTZ,
    rotated_at         TIMESTAMPTZ,
    rotation_count     INTEGER     NOT NULL DEFAULT 0,
    version            INTEGER     NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rate_limit_per_min INTEGER;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotation_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;
"#;

pub struct PostgresApiKeyStore {
    pool: PgPool,
}

impl PostgresApiKeyStore {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        let pool = crate::db::connect_pool(url, 5)?;
        Ok(Self { pool })
    }

    /// Remove all rows (test helper).
    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM api_keys")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl ApiKeyStore for PostgresApiKeyStore {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn create(
        &self,
        tenant: &str,
        name: &str,
        plaintext: Option<String>,
        options: crate::auth::NewKeyOptions,
    ) -> Result<(ApiKeyRecord, String), BrokerError> {
        let plaintext = plaintext.unwrap_or_else(crate::auth::generate_key);
        let hash = hash_key(&plaintext);
        let mut record = new_record(tenant, name, &plaintext);
        record.rate_limit_per_min = options.rate_limit_per_min;
        record.scope = options.scope.clone();
        record.expires_at = options.expires_at.clone();
        let expires_at = record
            .expires_at
            .as_deref()
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
            .map(|ts| ts.with_timezone(&chrono::Utc));
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;

        sqlx::query(
            "INSERT INTO api_keys
                 (id, tenant, name, key_hash, prefix, created_at, rate_limit_per_min, scope, expires_at)
             VALUES ($1, $2, $3, $4, $5, now(), $6, $7, $8)
             ON CONFLICT (key_hash) DO NOTHING",
        )
        .bind(&record.id)
        .bind(tenant)
        .bind(name)
        .bind(&hash)
        .bind(&record.prefix)
        .bind(options.rate_limit_per_min.map(|limit| limit as i32))
        .bind(sqlx::types::Json(&options.scope))
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(map)?;

        // Return the canonical record for this hash (existing one if it already existed).
        let row = sqlx::query("SELECT * FROM api_keys WHERE key_hash = $1")
            .bind(&hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok((decode(row)?, plaintext))
    }

    async fn authenticate(&self, plaintext: &str) -> Result<Option<ApiKeyRecord>, BrokerError> {
        let hash = hash_key(plaintext);
        let row = sqlx::query("SELECT * FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL")
            .bind(&hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(map)?;
        row.map(decode).transpose()
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ApiKeyRecord>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let rows = sqlx::query("SELECT * FROM api_keys WHERE tenant = $1 ORDER BY created_at DESC")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await
            .map_err(map)?;
        rows.into_iter().map(decode).collect()
    }

    async fn update(
        &self,
        tenant: &str,
        id: &str,
        scope: Option<crate::auth::KeyScope>,
        rate_limit_per_min: Option<Option<u32>>,
        expected_version: Option<u32>,
    ) -> Result<crate::auth::MutateOutcome<ApiKeyRecord>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query(
            "UPDATE api_keys
                SET scope = COALESCE($1, scope),
                    rate_limit_per_min = CASE WHEN $2 THEN $3 ELSE rate_limit_per_min END,
                    version = version + 1
              WHERE tenant = $4 AND id = $5 AND revoked_at IS NULL
                AND ($6::int IS NULL OR version = $6)",
        )
        .bind(scope.as_ref().map(sqlx::types::Json))
        .bind(rate_limit_per_min.is_some())
        .bind(rate_limit_per_min.flatten().map(|limit| limit as i32))
        .bind(tenant)
        .bind(id)
        .bind(expected_version.map(|version| version as i32))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        if result.rows_affected() == 0 {
            let current = sqlx::query(
                "SELECT version FROM api_keys WHERE tenant = $1 AND id = $2 AND revoked_at IS NULL",
            )
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
            tx.commit().await.map_err(map)?;
            return Ok(match current {
                Some(row) => crate::auth::MutateOutcome::Conflict {
                    current: row.get::<i32, _>("version").max(1) as u32,
                },
                None => crate::auth::MutateOutcome::NotFound,
            });
        }
        let row = sqlx::query("SELECT * FROM api_keys WHERE tenant = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(crate::auth::MutateOutcome::Done(decode(row)?))
    }

    async fn renew(
        &self,
        tenant: &str,
        id: &str,
        expires_at: Option<String>,
        expected_version: Option<u32>,
    ) -> Result<crate::auth::MutateOutcome<(ApiKeyRecord, String)>, BrokerError> {
        let plaintext = crate::auth::generate_key();
        let hash = hash_key(&plaintext);
        let prefix: String = plaintext.chars().take(12).collect();
        let expires_at = expires_at
            .as_deref()
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
            .map(|ts| ts.with_timezone(&chrono::Utc));
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query(
            "UPDATE api_keys
                SET key_hash = $1, prefix = $2, expires_at = $3,
                    rotated_at = now(), rotation_count = rotation_count + 1,
                    version = version + 1
              WHERE tenant = $4 AND id = $5 AND revoked_at IS NULL
                AND ($6::int IS NULL OR version = $6)",
        )
        .bind(&hash)
        .bind(&prefix)
        .bind(expires_at)
        .bind(tenant)
        .bind(id)
        .bind(expected_version.map(|version| version as i32))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        if result.rows_affected() == 0 {
            let current = sqlx::query(
                "SELECT version FROM api_keys WHERE tenant = $1 AND id = $2 AND revoked_at IS NULL",
            )
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
            tx.commit().await.map_err(map)?;
            return Ok(match current {
                Some(row) => crate::auth::MutateOutcome::Conflict {
                    current: row.get::<i32, _>("version").max(1) as u32,
                },
                None => crate::auth::MutateOutcome::NotFound,
            });
        }
        let row = sqlx::query("SELECT * FROM api_keys WHERE key_hash = $1")
            .bind(&hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(crate::auth::MutateOutcome::Done((decode(row)?, plaintext)))
    }

    async fn revoke(
        &self,
        tenant: &str,
        id: &str,
        expected_version: Option<u32>,
    ) -> Result<crate::auth::MutateOutcome<()>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = now(), version = version + 1
              WHERE tenant = $1 AND id = $2 AND revoked_at IS NULL
                AND ($3::int IS NULL OR version = $3)",
        )
        .bind(tenant)
        .bind(id)
        .bind(expected_version.map(|version| version as i32))
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        if result.rows_affected() == 0 {
            let current = sqlx::query(
                "SELECT version FROM api_keys WHERE tenant = $1 AND id = $2 AND revoked_at IS NULL",
            )
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map)?;
            tx.commit().await.map_err(map)?;
            return Ok(match current {
                Some(row) => crate::auth::MutateOutcome::Conflict {
                    current: row.get::<i32, _>("version").max(1) as u32,
                },
                None => crate::auth::MutateOutcome::NotFound,
            });
        }
        tx.commit().await.map_err(map)?;
        Ok(crate::auth::MutateOutcome::Done(()))
    }
}

fn decode(row: sqlx::postgres::PgRow) -> Result<ApiKeyRecord, BrokerError> {
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
    Ok(ApiKeyRecord {
        id: row.get("id"),
        tenant: row.get("tenant"),
        name: row.get("name"),
        prefix: row.get("prefix"),
        created_at: created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        revoked_at: revoked_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        rate_limit_per_min: row
            .get::<Option<i32>, _>("rate_limit_per_min")
            .and_then(|limit| u32::try_from(limit).ok())
            .filter(|limit| *limit > 0),
        scope: row
            .get::<sqlx::types::Json<crate::auth::KeyScope>, _>("scope")
            .0,
        expires_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")
            .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        rotated_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("rotated_at")
            .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        rotation_count: row.get::<i32, _>("rotation_count").max(0) as u32,
        version: row.get::<i32, _>("version").max(1) as u32,
    })
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
