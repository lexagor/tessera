//! Row-level security (skipped unless TEST_DATABASE_URL is set).
//!
//! Applies `infra/sql/rls.sql` and proves that a tenant transaction restricts even an
//! *unfiltered* query, while an administrative connection still sees all rows.

use std::path::PathBuf;

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

use tessera_broker::chain::{AppendOutcome, ChainEntry, ChainStore};
use tessera_broker::chain_pg::PostgresChainStore;
use tessera_broker::receipt::{
    new_receipt, payload_hash_hex, AuthorizationRef, CallRef, GrantRef, ReceiptSigner,
};

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn db_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn rls_sql() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../infra/sql/rls.sql");
    std::fs::read_to_string(path).expect("read rls.sql")
}

fn receipt(tenant: &str, agent: &str) -> tessera_broker::receipt::GrantReceipt {
    new_receipt(
        tenant,
        agent,
        "u",
        tessera_broker::canonical::keccak256_str("intent"),
        AuthorizationRef {
            decision: "allow".into(),
            policy: "p".into(),
            policy_version: 1,
            resource: "stripe:refunds.create".into(),
            anomaly_score: 0.0,
            policy_hash: None,
        },
        CallRef {
            tool: "stripe.refunds.create".into(),
            args_hash: tessera_broker::canonical::keccak256_str("args"),
            result_hash: None,
            tool_hash: None,
        },
        GrantRef {
            provider: "stripe".into(),
            ttl_s: 30,
            single_use: true,
            status: "issued".into(),
        },
    )
}

async fn append(store: &PostgresChainStore, signer: &ReceiptSigner, tenant: &str, agent: &str) {
    for _ in 0..8 {
        let head = store.head_hash(tenant, agent).await.unwrap();
        let mut r = receipt(tenant, agent);
        r.prev = head;
        signer.sign(&mut r).await.unwrap();
        let entry = ChainEntry {
            payload_hash: payload_hash_hex(&r).unwrap(),
            receipt: r,
        };
        if store.append(tenant, agent, entry).await.unwrap() == AppendOutcome::Appended {
            return;
        }
    }
    panic!("append contention");
}

#[tokio::test]
async fn rls_restricts_unfiltered_queries() {
    let Some(url) = db_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    // Fresh schema + RLS policies.
    let store = PostgresChainStore::new(&url).unwrap();
    store.reset().await.unwrap();
    store.truncate().await.unwrap();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_lazy(&url)
        .unwrap();
    sqlx::raw_sql(&rls_sql()).execute(&pool).await.unwrap();

    // RLS applies to non-superuser roles; production connects as one. Create a
    // non-login app role and grant it access for the assertions below.
    sqlx::raw_sql(
        "DO $$ BEGIN
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tessera_rls_test') THEN
                 CREATE ROLE tessera_rls_test NOLOGIN;
             END IF;
         END $$;
         GRANT USAGE ON SCHEMA public TO tessera_rls_test;
         GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tessera_rls_test;",
    )
    .execute(&pool)
    .await
    .unwrap();

    let signer = ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 1, ZERO_ADDR).unwrap();
    append(&store, &signer, "rls-a", "agent-a").await;
    append(&store, &signer, "rls-a", "agent-a").await;
    append(&store, &signer, "rls-b", "agent-b").await;

    // Store operations still work under RLS.
    assert_eq!(store.chain("rls-a", "agent-a").await.unwrap().len(), 2);

    // An *unfiltered* count as the app role sees only the current tenant's rows.
    let count_as_app = |tenant: Option<&'static str>| {
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL ROLE tessera_rls_test")
                .execute(&mut *tx)
                .await
                .unwrap();
            if let Some(tenant) = tenant {
                sqlx::query("SELECT set_config('app.tenant', $1, true)")
                    .bind(tenant)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let row = sqlx::query("SELECT count(*) AS n FROM receipt_chain")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            row.get::<i64, _>("n")
        }
    };
    assert_eq!(
        count_as_app(Some("rls-a")).await,
        2,
        "tenant A sees only its own rows"
    );
    assert_eq!(
        count_as_app(Some("rls-b")).await,
        1,
        "tenant B sees only its own rows"
    );
    // Administrative fallback: no GUC set -> policy allows the cross-tenant scan.
    assert_eq!(count_as_app(None).await, 3, "admin path sees all rows");

    // Administrative access (no GUC) still sees everything (scheduler/retention).
    let row = sqlx::query("SELECT count(*) AS n FROM receipt_chain")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("n"), 3);
}
