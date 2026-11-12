//! Database helpers.
//!
//! [`tenant_tx`] opens a transaction with the `app.tenant` GUC set (transaction-local), so
//! Postgres row-level-security policies can restrict tenant-scoped queries to the caller's
//! tenant — defense in depth against a query that forgets its `tenant = $n` predicate.
//!
//! The RLS policies (see `infra/sql/rls.sql`) treat an **unset** `app.tenant` as
//! "administrative access", so cross-tenant jobs (scheduler sweeps, retention) that do not
//! set the GUC keep working.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::error::BrokerError;

/// Pool options shared by every Postgres store: a bounded number of connections, a
/// generous-but-finite queue wait, and a server-side statement timeout so one pathological
/// query cannot pin a connection or a CPU slice indefinitely.
pub fn pool_options(max_connections: u32) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
}

/// Statement timeout applied to every pool (milliseconds). Long retention sweeps use
/// batched deletes, so this only catches runaway queries.
pub const STATEMENT_TIMEOUT_MS: u64 = 30_000;

/// Connect with [`pool_options`] and apply the statement timeout at the server level.
pub fn connect_pool(url: &str, max_connections: u32) -> Result<PgPool, BrokerError> {
    let options = pool_options(max_connections).after_connect(|conn, _meta| {
        Box::pin(async move {
            sqlx::query(&format!("SET statement_timeout = {STATEMENT_TIMEOUT_MS}"))
                .execute(conn)
                .await
                .map(|_| ())
        })
    });
    options
        .connect_lazy(url)
        .map_err(|e| BrokerError::Internal(format!("postgres pool: {e}")))
}

/// Begin a transaction scoped to `tenant` (`SET LOCAL app.tenant`).
pub async fn tenant_tx<'a>(
    pool: &'a PgPool,
    tenant: &str,
) -> Result<Transaction<'a, Postgres>, BrokerError> {
    let mut tx = pool.begin().await.map_err(map)?;
    sqlx::query("SELECT set_config('app.tenant', $1, true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(map)?;
    Ok(tx)
}

/// Fail production startup when the runtime database role bypasses RLS.
pub async fn assert_non_superuser(url: &str) -> Result<(), BrokerError> {
    let pool = connect_pool(url, 1)?;
    let result = sqlx::query("SELECT current_setting('is_superuser') AS is_superuser")
        .fetch_one(&pool)
        .await
        .map_err(map);
    pool.close().await;
    let row = result?;
    let is_superuser: String = row.try_get("is_superuser").unwrap_or_default();
    if is_superuser == "on" {
        return Err(BrokerError::Invalid(
            "DATABASE_URL user is a Postgres superuser; use the non-superuser tessera_app role"
                .into(),
        ));
    }
    Ok(())
}

pub fn map(err: sqlx::Error) -> BrokerError {
    BrokerError::Internal(format!("postgres: {err}"))
}
