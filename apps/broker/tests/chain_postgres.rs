//! Postgres-backed receipt-chain integration test.
//!
//! Skipped unless `TEST_DATABASE_URL` is set, e.g.
//! `TEST_DATABASE_URL=postgres://a@127.0.0.1:5432/tessera_test cargo test`.

use std::sync::Arc;

use tessera_broker::anchoring::{AnchorStore, AnchorTarget, AnchorTargetStore, ClaimOutcome};
use tessera_broker::anchoring_pg::PostgresAnchoring;
use tessera_broker::auth::ApiKeyStore;
use tessera_broker::auth_pg::PostgresApiKeyStore;
use tessera_broker::authorize::{AuthorizeRequest, AuthorizeService, RecordRequest};
use tessera_broker::chain::{verify_chain, ChainStore};
use tessera_broker::chain_pg::PostgresChainStore;
use tessera_broker::issuers::mock::MockIssuer;
use tessera_broker::issuers::stripe::{GrantStore, PostgresGrantStore, StoredGrant};
use tessera_broker::issuers::{IssuerRegistry, ProxySpec};
use tessera_broker::policy::{
    demo_policy, Constraint, InMemoryPolicyStore, Policy, PolicyMode, PolicyStore,
};
use tessera_broker::policy_pg::PostgresPolicyStore;
use tessera_broker::receipt::ReceiptSigner;
use tessera_broker::revocation::RevocationStore;
use tessera_broker::revocation_pg::PostgresRevocationStore;
use tessera_broker::secrets::Envelope;
use tessera_broker::telemetry::{observe_fields, propose, Observation, TelemetryStore};
use tessera_broker::telemetry_pg::PostgresTelemetryStore;

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

fn db_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Serialize the Postgres tests (they share one database).
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn request(agent: &str, amount: i64) -> AuthorizeRequest {
    AuthorizeRequest {
        agent_id: agent.into(),
        user_id: "user_42".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund a duplicate charge".into(),
        args: serde_json::json!({ "amount": amount }),
        tool_schema_hash: None,
        ..Default::default()
    }
}

fn service(store: PostgresChainStore) -> Arc<AuthorizeService> {
    let signer =
        Arc::new(ReceiptSigner::from_hex_or_random(Some(TEST_KEY), 84532, ZERO_ADDR).unwrap());
    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(MockIssuer::new("stripe")));
    Arc::new(AuthorizeService {
        policies: Arc::new(InMemoryPolicyStore::new()),
        issuers: Arc::new(issuers),
        authority_hmac_secret: None,
        authority_require_token: false,
        signer,
        chain: Arc::new(store),
        telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        anchor: None,
        anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: Arc::new(tessera_broker::anchoring::MemoryAnchorTargetStore::new()),
        secrets: None,
        rpc_policy: Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min: None,
        retention_days: 90,
        anchor_confirmations: 12,
        anchor_reorg_grace_secs: 300,
        revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http: reqwest::Client::new(),
        alert_acks: Arc::new(tessera_broker::alert_acks::MemoryAlertAcks::new()),
        key_events: Arc::new(tessera_broker::key_events::MemoryKeyEvents::new()),
        chain_checkpoints: Arc::new(
            tessera_broker::chain_checkpoints::MemoryChainCheckpoints::new(),
        ),
        quota: Arc::new(tessera_broker::quota::QuotaManager::disabled()),
        remediation_policies: Arc::new(
            tessera_broker::remediation::MemoryRemediationPolicies::new(),
        ),
        tool_pins: Arc::new(tessera_broker::tool_pins::MemoryToolPins::new()),
        alert_router: Arc::new(tessera_broker::alerts::AlertRouter::new(
            Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
            None,
            None,
        )),
        key_expiry_alert_days: 0,
        key_rotation_max_age_hours: None,
        default_ttl_seconds: 30,
        max_ttl_seconds: 3600,
        signing_key_history: Vec::new(),
        anchor_gap_threshold: 100,
        ledger_retention_days: 0,
        archive_dir: None,
        archive_interval_secs: 3600,
        archive_replica_dir: None,
        archive_retention_days: 0,
        alert_webhook_url: None,
        alert_webhook_token: None,
        alert_repeat_secs: 3600,
        alert_retry_secs: 60,
        gap_alerts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        tool_rate_limits: Vec::new(),
        demo_policy: Some(demo_policy()),
    })
}

#[tokio::test]
async fn postgres_chain_authorize_record_persist_and_verify() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresChainStore::new(&url).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();

    let svc = service(store);

    let a1 = svc
        .authorize("acme", request("billing", 100))
        .await
        .unwrap();
    let a2 = svc
        .authorize("acme", request("billing", 101))
        .await
        .unwrap();
    assert_eq!(svc.chain.len("acme", "billing").await.unwrap(), 2);
    // second receipt links to the first
    assert_eq!(a2.receipt.prev.as_deref(), Some(a1.receipt_id.as_str()));
    // chains are isolated per agent
    assert_eq!(svc.chain.len("acme", "other").await.unwrap(), 0);

    let rec = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing".into(),
                receipt_id: a2.receipt_id.clone(),
                result_hash: format!("0x{}", "11".repeat(32)),
                status: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(rec.chain_length, 3);
    assert!(svc.verify_chain("acme", "billing").await.unwrap());

    // A fresh store instance sees the same persisted chain.
    let store2 = PostgresChainStore::new(&url).unwrap();
    let chain = store2.chain("acme", "billing").await.unwrap();
    assert_eq!(chain.len(), 3);
    assert!(verify_chain(&chain, &svc.signer, Some(&svc.signer.address_hex())).unwrap());
    // the outcome receipt is retrievable by payload hash
    let found = store2
        .find("acme", "billing", &rec.receipt_id)
        .await
        .unwrap();
    assert!(found.is_some());

    // A late outcome for the first authorization links by id and appends at the head.
    let late = svc
        .record(
            "acme",
            RecordRequest {
                agent_id: "billing".into(),
                receipt_id: a1.receipt_id.clone(),
                result_hash: format!("0x{}", "22".repeat(32)),
                status: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!late.duplicate);
    assert_eq!(
        late.receipt.authorization_receipt_id.as_deref(),
        Some(a1.receipt_id.as_str())
    );
    assert_eq!(late.receipt.prev.as_deref(), Some(rec.receipt_id.as_str()));
    let found = store2
        .find_outcome_for_authorization("acme", "billing", &a1.receipt_id)
        .await
        .unwrap()
        .expect("late outcome");
    assert_eq!(found.payload_hash, late.receipt_id);
}

#[tokio::test]
async fn postgres_chain_handles_same_agent_concurrency() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresChainStore::new(&url).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();
    let svc = service(store);

    let mut handles = Vec::new();
    for i in 0..48i64 {
        let svc = svc.clone();
        handles.push(tokio::spawn(async move {
            svc.authorize("acme", request("concurrent", 100 + i))
                .await
                .unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(
        svc.chain.len("acme", "concurrent").await.unwrap(),
        48,
        "every concurrent authorization should append exactly once"
    );
    assert!(svc.verify_chain("acme", "concurrent").await.unwrap());
}

#[tokio::test]
async fn postgres_policy_crud() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let store = PostgresPolicyStore::new(&url).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();

    let policy = Policy {
        id: "acme-refunds".into(),
        version: 1,
        name: "Refunds".into(),
        grants: vec![],
        fail_open: false,
        mode: PolicyMode::Enforce,
        limits: Default::default(),
    };
    store.upsert("acme", policy.clone()).await.unwrap();
    assert_eq!(store.list("acme").await.unwrap().len(), 1);
    assert!(store.get("acme", "acme-refunds").await.unwrap().is_some());

    // Same id+version with different content is rejected (history is immutable).
    let mut changed = policy.clone();
    changed.name = "Changed".into();
    let err = store.upsert("acme", changed).await.unwrap_err();
    assert!(matches!(err, tessera_broker::BrokerError::Invalid(_)));

    // upsert replaces
    let mut updated = policy;
    updated.version = 5;
    store.upsert("acme", updated).await.unwrap();
    assert_eq!(
        store
            .get("acme", "acme-refunds")
            .await
            .unwrap()
            .unwrap()
            .version,
        5
    );
    assert_eq!(store.list("acme").await.unwrap().len(), 1);

    // tenants are isolated
    assert!(store.list("other").await.unwrap().is_empty());

    assert!(store.delete("acme", "acme-refunds").await.unwrap());
    assert!(!store.delete("acme", "acme-refunds").await.unwrap());
}

#[tokio::test]
async fn postgres_partitioning_and_retention() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresChainStore::new(&url).unwrap();
    store.reset().await.unwrap();
    assert!(
        store.is_partitioned().await.unwrap(),
        "expected a partitioned table"
    );

    let svc = service(PostgresChainStore::new(&url).unwrap());
    for _ in 0..3 {
        svc.authorize("acme", request("billing", 100))
            .await
            .unwrap();
    }
    svc.authorize("acme", request("other", 100)).await.unwrap();
    assert_eq!(svc.chain.len("acme", "billing").await.unwrap(), 3);
    assert!(svc.verify_chain("acme", "billing").await.unwrap());

    // Cutoff in the past: nothing pruned.
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    assert_eq!(svc.chain.prune_idle_agents(past).await.unwrap(), 0);

    // Cutoff in the future: all agents pruned.
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    assert_eq!(svc.chain.prune_idle_agents(future).await.unwrap(), 4);
    assert_eq!(svc.chain.len("acme", "billing").await.unwrap(), 0);
    assert_eq!(svc.chain.len("acme", "other").await.unwrap(), 0);
}

#[tokio::test]
async fn postgres_api_keys() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresApiKeyStore::new(&url).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();

    let (record, key) = store
        .create(
            "acme",
            "ci",
            None,
            tessera_broker::auth::NewKeyOptions {
                rate_limit_per_min: Some(7),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(key.starts_with("tsk_"));
    assert_eq!(
        store
            .authenticate(&key)
            .await
            .unwrap()
            .and_then(|r| r.rate_limit_per_min),
        Some(7),
        "per-key budget must survive the round trip"
    );
    assert_eq!(
        store.authenticate(&key).await.unwrap().map(|r| r.tenant),
        Some("acme".to_string())
    );
    assert_eq!(store.list("acme").await.unwrap().len(), 1);
    assert!(store.list("other").await.unwrap().is_empty());

    // creating the same plaintext again is idempotent
    let (again, _) = store
        .create("acme", "dup", Some(key.clone()), Default::default())
        .await
        .unwrap();
    assert_eq!(again.id, record.id);
    assert_eq!(store.list("acme").await.unwrap().len(), 1);

    use tessera_broker::auth::MutateOutcome;
    assert_eq!(
        store.revoke("acme", &record.id, None).await.unwrap(),
        MutateOutcome::Done(())
    );
    assert!(store.authenticate(&key).await.unwrap().is_none());
    assert_eq!(
        store.revoke("acme", &record.id, None).await.unwrap(),
        MutateOutcome::NotFound
    );
}

#[tokio::test]
async fn postgres_telemetry_and_proposal() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresTelemetryStore::new(&url).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();

    for (amount, currency) in [(100.0, "usd"), (700.0, "usd"), (250.0, "eur")] {
        let mut fields = Vec::new();
        observe_fields(
            &serde_json::json!({ "amount": amount, "currency": currency }),
            &mut fields,
        );
        store
            .record(&Observation {
                tenant: "acme".into(),
                resource: "stripe:refunds.create".into(),
                fields,
            })
            .await
            .unwrap();
    }

    let stats = store.stats("acme").await.unwrap();
    let proposal = propose(&stats);
    assert_eq!(proposal.policy.grants.len(), 1);
    assert!(proposal.policy.grants[0]
        .constraints
        .iter()
        .any(|c| matches!(c, Constraint::MaxNumber { value, .. } if *value == 700.0)));
    assert!(proposal.policy.grants[0]
        .constraints
        .iter()
        .any(|c| matches!(c, Constraint::Allowlist { field, .. } if field == "currency")));
    assert!(store.stats("other").await.unwrap().is_empty());

    // idle telemetry older than the cutoff is pruned
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    assert_eq!(store.prune_idle_before(past).await.unwrap(), 0);
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    assert!(store.prune_idle_before(future).await.unwrap() >= 1);
    assert!(store.stats("acme").await.unwrap().is_empty());
}

#[tokio::test]
async fn postgres_revocations() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresRevocationStore::new(&url).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();

    assert!(!store.is_revoked("acme", "g1").await.unwrap());
    let event = store
        .revoke("acme", "g1", "grant", Some("leak".into()))
        .await
        .unwrap();
    assert_eq!(event.kind, "grant");
    assert!(store.is_revoked("acme", "g1").await.unwrap());
    assert_eq!(store.list("acme").await.unwrap().len(), 1);
    assert!(!store.is_revoked("other", "g1").await.unwrap());

    // idempotent per (tenant, target)
    store.revoke("acme", "g1", "grant", None).await.unwrap();
    assert_eq!(store.list("acme").await.unwrap().len(), 1);
}

#[tokio::test]
async fn postgres_anchoring_records_and_targets() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresAnchoring::new(&url).unwrap();
    <PostgresAnchoring as AnchorStore>::migrate(&store)
        .await
        .unwrap();
    store.truncate().await.unwrap();

    store
        .record(tessera_broker::anchoring::new_record(
            "acme",
            "a1",
            "0xroot",
            3,
            84532,
            "0xcontract",
            "0xtx",
        ))
        .await
        .unwrap();
    assert_eq!(AnchorStore::list(&store, "acme").await.unwrap().len(), 1);
    // confirmation updates status + block number
    let record = AnchorStore::list(&store, "acme").await.unwrap().remove(0);
    assert_eq!(store.pending("acme").await.unwrap().len(), 1);
    store
        .update("acme", &record.id, "confirmed", Some(123))
        .await
        .unwrap();
    assert_eq!(
        store
            .latest("acme", "a1")
            .await
            .unwrap()
            .unwrap()
            .block_number,
        Some(123)
    );
    // "confirmed" is still pending finality; "finalized" clears it
    assert_eq!(store.pending("acme").await.unwrap().len(), 1);
    store
        .update("acme", &record.id, "finalized", Some(123))
        .await
        .unwrap();
    assert!(store.pending("acme").await.unwrap().is_empty());
    assert_eq!(
        store
            .latest("acme", "a1")
            .await
            .unwrap()
            .unwrap()
            .merkle_root,
        "0xroot"
    );
    assert!(store.latest("acme", "other").await.unwrap().is_none());

    store
        .set(
            "acme",
            AnchorTarget {
                chain_id: 8453,
                rpc_url: "https://mainnet.base.org".into(),
                contract: "0xabc".into(),
                private_key: None,
                signer_history: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(store.get("acme").await.unwrap().unwrap().chain_id, 8453);
    // upsert replaces
    store
        .set(
            "acme",
            AnchorTarget {
                chain_id: 1,
                rpc_url: "https://eth.example".into(),
                contract: "0xdef".into(),
                private_key: Some("0xkey".into()),
                signer_history: vec!["0x1111111111111111111111111111111111111111".into()],
            },
        )
        .await
        .unwrap();
    assert_eq!(store.get("acme").await.unwrap().unwrap().chain_id, 1);
    assert_eq!(
        store.get("acme").await.unwrap().unwrap().signer_history,
        vec!["0x1111111111111111111111111111111111111111".to_string()],
        "signer history must survive the round trip"
    );
    assert_eq!(AnchorTargetStore::list(&store).await.unwrap().len(), 1);
}

#[tokio::test]
async fn postgres_anchor_claims_prevent_duplicate_submissions() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;

    let store = PostgresAnchoring::new(&url).unwrap();
    <PostgresAnchoring as AnchorStore>::migrate(&store)
        .await
        .unwrap();
    store.truncate().await.unwrap();

    let first = store
        .claim("acme", "a1", "0xroot", 2, 1, "0xc")
        .await
        .unwrap();
    let id = match first {
        ClaimOutcome::Claimed { id } => id,
        other => panic!("expected claim, got {other:?}"),
    };
    // a second claim for the same live root is refused
    assert_eq!(
        store
            .claim("acme", "a1", "0xroot", 2, 1, "0xc")
            .await
            .unwrap(),
        ClaimOutcome::AlreadyClaimed
    );

    store
        .settle("acme", &id, "0xtx", "confirmed", Some(5))
        .await
        .unwrap();
    let rec = store.latest("acme", "a1").await.unwrap().unwrap();
    assert_eq!(rec.tx_hash.as_deref(), Some("0xtx"));
    assert_eq!(rec.block_number, Some(5));

    // after a reorg the partial unique index no longer holds the root, so a new claim works
    store.update("acme", &id, "reorged", None).await.unwrap();
    assert!(matches!(
        store
            .claim("acme", "a1", "0xroot", 2, 1, "0xc")
            .await
            .unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
}

#[tokio::test]
async fn pools_apply_a_server_side_statement_timeout() {
    let Some(url) = db_url() else {
        return;
    };
    let pool = tessera_broker::db::connect_pool(&url, 2).unwrap();
    let (timeout,): (String,) = sqlx::query_as("SHOW statement_timeout")
        .fetch_one(&pool)
        .await
        .unwrap();
    // Postgres normalizes the value (e.g. "30s") — compare in milliseconds.
    let millis = if let Some(raw) = timeout.strip_suffix("ms") {
        raw.parse::<u64>().unwrap()
    } else if let Some(raw) = timeout.strip_suffix('s') {
        raw.parse::<u64>().unwrap() * 1_000
    } else {
        panic!("unexpected statement_timeout format: {timeout}");
    };
    assert_eq!(millis, tessera_broker::db::STATEMENT_TIMEOUT_MS);
}

#[tokio::test]
async fn postgres_grants_are_durable_and_single_use() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let envelope = Arc::new(Envelope::from_hex(&"11".repeat(32)).unwrap());
    let store = PostgresGrantStore::new(&url, Some(envelope)).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();

    let grant_id = "grant_test".to_string();
    store
        .insert(
            grant_id.clone(),
            StoredGrant {
                secret_key: "rk_test".into(),
                tenant: "t".into(),
                resource: "stripe:refunds.create".into(),
                args_hash: "0xabc".into(),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
                spec: ProxySpec {
                    base_url: "https://api.stripe.com".into(),
                    auth_header: "authorization".into(),
                    auth_scheme: "Bearer".into(),
                },
                authorization_receipt_id: None,
                action_id: None,
                agent_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(store.count().await.unwrap(), 1);
    assert_eq!(
        store.peek("t", &grant_id).await.unwrap().as_deref(),
        Some("stripe:refunds.create")
    );

    // Bind the grant to its authorization before redemption.
    assert!(store
        .bind(
            "t",
            &grant_id,
            &format!("0x{}", "aa".repeat(32)),
            "action_1",
            "billing"
        )
        .await
        .unwrap());

    // Wrong tenant and wrong args do not consume the grant.
    assert!(store.redeem("other", &grant_id, "0xabc").await.is_err());
    assert!(store.redeem("t", &grant_id, "0xdef").await.is_err());
    let redeemed = store.redeem("t", &grant_id, "0xabc").await.unwrap();
    assert_eq!(redeemed.secret, "rk_test");
    assert_eq!(redeemed.resource, "stripe:refunds.create");
    assert_eq!(
        redeemed.authorization_receipt_id.as_deref(),
        Some(format!("0x{}", "aa".repeat(32)).as_str())
    );
    assert_eq!(redeemed.action_id.as_deref(), Some("action_1"));
    assert_eq!(redeemed.agent_id.as_deref(), Some("billing"));
    assert_eq!(store.count().await.unwrap(), 0);

    // Revocation is tenant-scoped and idempotent.
    store
        .insert(
            "grant_revoke".into(),
            StoredGrant {
                secret_key: "rk_test".into(),
                tenant: "t".into(),
                resource: "stripe:refunds.create".into(),
                args_hash: "0xabc".into(),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
                spec: ProxySpec {
                    base_url: "https://api.stripe.com".into(),
                    auth_header: "authorization".into(),
                    auth_scheme: "Bearer".into(),
                },
                authorization_receipt_id: None,
                action_id: None,
                agent_id: None,
            },
        )
        .await
        .unwrap();
    assert!(!store.revoke("other", "grant_revoke").await.unwrap());
    assert!(store.revoke("t", "grant_revoke").await.unwrap());
    assert!(!store.revoke("t", "grant_revoke").await.unwrap());
}

#[tokio::test]
async fn postgres_grant_store_is_bounded() {
    let Some(url) = db_url() else {
        eprintln!("skipping postgres test: TEST_DATABASE_URL not set");
        return;
    };
    let _guard = DB_LOCK.lock().await;
    let envelope = Arc::new(Envelope::from_hex(&"11".repeat(32)).unwrap());
    let store = PostgresGrantStore::with_max_grants(&url, Some(envelope), 2).unwrap();
    store.migrate().await.unwrap();
    store.truncate().await.unwrap();
    for index in 0..6i64 {
        store
            .insert(
                format!("grant_bound_{index}"),
                StoredGrant {
                    secret_key: "rk_test".into(),
                    tenant: "t".into(),
                    resource: "stripe:refunds.create".into(),
                    args_hash: "0xabc".into(),
                    expires_at: chrono::Utc::now() + chrono::Duration::seconds(60 + index),
                    spec: ProxySpec {
                        base_url: "https://api.stripe.com".into(),
                        auth_header: "authorization".into(),
                        auth_scheme: "Bearer".into(),
                    },
                    authorization_receipt_id: None,
                    action_id: None,
                    agent_id: None,
                },
            )
            .await
            .unwrap();
    }
    assert!(store.count().await.unwrap() <= 2);
}
