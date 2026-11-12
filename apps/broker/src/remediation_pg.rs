//! Postgres-backed auto-remediation policies.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::error::BrokerError;
use crate::remediation::{RemediationPolicy, RemediationPolicyStore};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS remediation_policies (
    tenant           TEXT        PRIMARY KEY,
    template         TEXT        NOT NULL,
    template_version INTEGER,
    enabled          BOOLEAN     NOT NULL DEFAULT true,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE remediation_policies ADD COLUMN IF NOT EXISTS template_version INTEGER;
"#;

pub struct PostgresRemediationPolicies {
    pool: PgPool,
}

impl PostgresRemediationPolicies {
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
impl RemediationPolicyStore for PostgresRemediationPolicies {
    async fn migrate(&self) -> Result<(), BrokerError> {
        sqlx::raw_sql(DDL).execute(&self.pool).await.map_err(map)?;
        Ok(())
    }

    async fn set(&self, tenant: &str, policy: RemediationPolicy) -> Result<(), BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        sqlx::query(
            "INSERT INTO remediation_policies (tenant, template, template_version, enabled, updated_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tenant) DO UPDATE SET
                 template = EXCLUDED.template,
                 template_version = EXCLUDED.template_version,
                 enabled = EXCLUDED.enabled,
                 updated_at = now()",
        )
        .bind(tenant)
        .bind(&policy.template)
        .bind(policy.template_version.map(|version| version as i32))
        .bind(policy.enabled)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(())
    }

    async fn get(&self, tenant: &str) -> Result<Option<RemediationPolicy>, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let row = sqlx::query(
            "SELECT template, enabled, updated_at FROM remediation_policies WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map)?;
        tx.commit().await.map_err(map)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
        Ok(Some(RemediationPolicy {
            template: row.get("template"),
            template_version: row
                .get::<Option<i32>, _>("template_version")
                .and_then(|version| u32::try_from(version).ok()),
            enabled: row.get("enabled"),
            updated_at: updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }))
    }

    async fn delete(&self, tenant: &str) -> Result<bool, BrokerError> {
        let mut tx = crate::db::tenant_tx(&self.pool, tenant).await?;
        let result = sqlx::query("DELETE FROM remediation_policies WHERE tenant = $1")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(map)?;
        tx.commit().await.map_err(map)?;
        Ok(result.rows_affected() > 0)
    }
}
