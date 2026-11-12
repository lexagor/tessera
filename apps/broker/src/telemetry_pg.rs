//! Postgres-backed telemetry store.

use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::error::BrokerError;
use crate::telemetry::{
    FieldStat, Observation, ObservedField, TelemetryStore, ALLOWLIST_MAX_VALUES, MAX_TEXT_VALUES,
};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS telemetry_calls (
    tenant   TEXT   NOT NULL,
    resource TEXT   NOT NULL,
    calls    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, resource)
);
ALTER TABLE telemetry_calls ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE TABLE IF NOT EXISTS telemetry_fields (
    tenant     TEXT NOT NULL,
    resource   TEXT NOT NULL,
    field      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value_text TEXT NOT NULL DEFAULT '',
    hits       BIGINT NOT NULL DEFAULT 0,
    min_num    DOUBLE PRECISION,
    max_num    DOUBLE PRECISION,
    PRIMARY KEY (tenant, resource, field, kind, value_text)
);
"#;

pub struct PostgresTelemetryStore {
    pool: PgPool,
}

impl PostgresTelemetryStore {
    pub fn new(url: &str) -> Result<Self, BrokerError> {
        let pool = crate::db::connect_pool(url, 5)?;
        Ok(Self { pool })
    }

    pub async fn truncate(&self) -> Result<(), BrokerError> {
        sqlx::query("DELETE FROM telemetry_fields")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        sqlx::query("DELETE FROM telemetry_calls")
            .execute(&self.pool)
            .await
            .map_err(map)?;
        Ok(())
    }
}

#[async_trait]
impl TelemetryStore for PostgresTelemetryStore {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn record(&self, obs: &Observation) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, &obs.tenant).await?;

        sqlx::query(
            "INSERT INTO telemetry_calls (tenant, resource, calls, updated_at) VALUES ($1, $2, 1, now())
             ON CONFLICT (tenant, resource) DO UPDATE SET calls = telemetry_calls.calls + 1, updated_at = now()",
        )
        .bind(&obs.tenant)
        .bind(&obs.resource)
        .execute(&mut *tx)
        .await
        .map_err(map)?;

        for field in &obs.fields {
            match field {
                ObservedField::Number { field, value } => {
                    sqlx::query(
                        "INSERT INTO telemetry_fields (tenant, resource, field, kind, value_text, hits, min_num, max_num)
                         VALUES ($1, $2, $3, 'number', '', 1, $4, $4)
                         ON CONFLICT (tenant, resource, field, kind, value_text)
                         DO UPDATE SET hits = telemetry_fields.hits + 1,
                                       min_num = LEAST(telemetry_fields.min_num, EXCLUDED.min_num),
                                       max_num = GREATEST(telemetry_fields.max_num, EXCLUDED.max_num)",
                    )
                    .bind(&obs.tenant)
                    .bind(&obs.resource)
                    .bind(field)
                    .bind(*value)
                    .execute(&mut *tx)
                    .await
                    .map_err(map)?;
                }
                ObservedField::Text { field, value } => {
                    // New distinct values are only inserted while the field is under the
                    // cardinality cap; existing values keep incrementing.
                    sqlx::query(
                        "INSERT INTO telemetry_fields (tenant, resource, field, kind, value_text, hits)
                         SELECT $1, $2, $3, 'string', $4, 1
                          WHERE (SELECT count(*) FROM telemetry_fields
                                  WHERE tenant = $1 AND resource = $2 AND field = $3 AND kind = 'string') < $5
                         ON CONFLICT (tenant, resource, field, kind, value_text)
                         DO UPDATE SET hits = telemetry_fields.hits + 1",
                    )
                    .bind(&obs.tenant)
                    .bind(&obs.resource)
                    .bind(field)
                    .bind(value)
                    .bind(MAX_TEXT_VALUES as i64)
                    .execute(&mut *tx)
                    .await
                    .map_err(map)?;
                }
            }
        }

        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn prune_idle_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        let mut tx = self.pool.begin().await.map_err(map)?;
        let fields = sqlx::query(
            "DELETE FROM telemetry_fields
              WHERE (tenant, resource) IN (
                    SELECT tenant, resource FROM telemetry_calls WHERE updated_at < $1
              )",
        )
        .bind(cutoff)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        let calls = sqlx::query("DELETE FROM telemetry_calls WHERE updated_at < $1")
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(calls.rows_affected() + fields.rows_affected())
    }

    async fn stats(&self, tenant: &str) -> Result<Vec<FieldStat>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let calls_rows =
            sqlx::query("SELECT resource, calls FROM telemetry_calls WHERE tenant = $1")
                .bind(tenant)
                .fetch_all(&mut *tx)
                .await
                .map_err(map)?;
        let calls: HashMap<String, u64> = calls_rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("resource"),
                    r.get::<i64, _>("calls") as u64,
                )
            })
            .collect();

        let rows = sqlx::query(
            "SELECT resource, field, kind, value_text, hits, min_num, max_num
               FROM telemetry_fields WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(map)?;

        // (resource, field) -> accumulated
        let mut numbers: HashMap<(String, String), (u64, f64, f64)> = HashMap::new();
        let mut strings: HashMap<(String, String), HashMap<String, u64>> = HashMap::new();

        for row in rows {
            let resource: String = row.get("resource");
            let field: String = row.get("field");
            let kind: String = row.get("kind");
            let hits = row.get::<i64, _>("hits") as u64;
            match kind.as_str() {
                "number" => {
                    let min = row.get::<Option<f64>, _>("min_num").unwrap_or(0.0);
                    let max = row.get::<Option<f64>, _>("max_num").unwrap_or(0.0);
                    numbers
                        .entry((resource, field))
                        .and_modify(|e| {
                            e.0 += hits;
                            e.1 = e.1.min(min);
                            e.2 = e.2.max(max);
                        })
                        .or_insert((hits, min, max));
                }
                _ => {
                    let value: String = row.get("value_text");
                    *strings
                        .entry((resource, field))
                        .or_default()
                        .entry(value)
                        .or_insert(0) += hits;
                }
            }
        }

        let mut out = Vec::new();
        for ((resource, field), (hits, min, max)) in numbers {
            out.push(FieldStat {
                total_calls: calls.get(&resource).copied().unwrap_or(0),
                resource,
                field,
                kind: "number".into(),
                count: hits,
                min: Some(min),
                max: Some(max),
                values: vec![],
                truncated: false,
            });
        }
        for ((resource, field), values) in strings {
            let mut list: Vec<String> = values.keys().cloned().collect();
            list.sort();
            let truncated = list.len() > ALLOWLIST_MAX_VALUES;
            out.push(FieldStat {
                total_calls: calls.get(&resource).copied().unwrap_or(0),
                resource,
                field,
                kind: "string".into(),
                count: values.values().sum(),
                min: None,
                max: None,
                values: list,
                truncated,
            });
        }
        out.sort_by(|a, b| (&a.resource, &a.field).cmp(&(&b.resource, &b.field)));
        Ok(out)
    }
}

fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
