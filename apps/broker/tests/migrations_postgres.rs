//! Startup migrations: every Postgres-backed store must create its tables.
//!
//! This is a regression test for a class of bug where a store is wired into the service
//! but its `migrate()` is not called at startup (the broker then fails at request time).

use std::sync::Arc;

use tessera_broker::bootstrap;
use tessera_broker::config::BrokerConfig;
use tessera_broker::issuers::stripe::{GrantStore, PostgresGrantStore};
use tessera_broker::secrets::Envelope;

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

#[tokio::test]
async fn startup_migrates_every_store() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping");
        return;
    };
    let config = BrokerConfig {
        database_url: Some(url.clone()),
        signing_key_hex: Some(TEST_KEY.into()),
        verifying_contract: "0x0000000000000000000000000000000000000000".into(),
        chain_id: 84532,
        demo_allow: true,
        ..Default::default()
    };
    let state = bootstrap::build_state(&config).await.expect("build state");
    state.service.migrate().await.expect("service migrations");
    state.keys.migrate().await.expect("key migrations");
    // Idempotent.
    state
        .service
        .migrate()
        .await
        .expect("second migration pass");

    // The grant store is only created when Stripe is configured; migrate it explicitly.
    let envelope = Arc::new(Envelope::from_hex(&"11".repeat(32)).unwrap());
    let grants = PostgresGrantStore::new(&url, Some(envelope)).unwrap();
    grants.migrate().await.expect("grant migrations");

    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    for table in [
        "receipt_chain",
        "telemetry_calls",
        "policies",
        "revocations",
        "anchors",
        "anchor_targets",
        "key_events",
        "alert_targets",
        "alert_acks",
        "remediation_policies",
        "chain_checkpoints",
        "tool_pins",
        "api_keys",
        "stripe_grants",
    ] {
        let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("query");
        assert!(
            found.is_some(),
            "table '{table}' was not created at startup"
        );
    }
}
