//! On-chain anchoring, end to end against a local `anvil` node.
//!
//! Skipped unless `anvil` is on PATH and the `ReceiptAnchor` artifact is built:
//!   (cd contracts/receipts && forge build)
//!   PATH="$HOME/.foundry/bin:$PATH" cargo test --test anchor_eth

use std::process::{Child, Command};
use std::time::Duration;

use tessera_broker::eth::{AnchorSubmitter, EthSigner, RpcClient};
use tessera_broker::merkle::keccak;

const DEV_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PORT: u16 = 8546;

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn anvil_available() -> bool {
    Command::new("anvil")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn artifact_bytecode() -> Option<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/receipts/out/ReceiptAnchor.sol/ReceiptAnchor.json"
    );
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let object = json.get("bytecode")?.get("object")?.as_str()?;
    hex::decode(object.trim_start_matches("0x")).ok()
}

async fn wait_for_node(rpc: &RpcClient) -> bool {
    for _ in 0..50 {
        if rpc.chain_id().await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn wait_for_tx(rpc: &RpcClient, hash: &str) -> bool {
    for _ in 0..50 {
        if rpc.transaction_succeeded(hash).await.unwrap_or(false) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn anchor_end_to_end_on_anvil() {
    if !anvil_available() {
        eprintln!("skipping: anvil not on PATH");
        return;
    }
    let Some(bytecode) = artifact_bytecode() else {
        eprintln!("skipping: ReceiptAnchor artifact not built (run `forge build`)");
        return;
    };

    let _child = KillOnDrop(
        Command::new("anvil")
            .args([
                "--port",
                &PORT.to_string(),
                "--chain-id",
                "31337",
                "--silent",
            ])
            .spawn()
            .expect("failed to spawn anvil"),
    );

    let url = format!("http://127.0.0.1:{PORT}");
    let rpc = RpcClient::new(&url);
    assert!(wait_for_node(&rpc).await, "anvil did not become ready");

    // Deploy ReceiptAnchor.
    let signer = EthSigner::from_hex(DEV_PK).unwrap();
    let chain_id = rpc.chain_id().await.unwrap();
    let (deploy_hash, contract) = rpc.deploy(&signer, &bytecode, chain_id).await.unwrap();
    assert!(
        wait_for_tx(&rpc, &deploy_hash).await,
        "contract deploy failed"
    );
    let contract_hex = format!("0x{}", hex::encode(contract));

    // Submit an anchor batch through the real AnchorSubmitter.
    let submitter = AnchorSubmitter::new(&url, DEV_PK, &contract_hex).unwrap();
    let tenant = keccak(b"acme");
    let root = keccak(b"root");
    let tx_hash = submitter.submit(tenant, root, 2).await.unwrap();
    assert!(
        submitter.wait_for_success(&tx_hash, 50).await.unwrap(),
        "anchor tx failed"
    );

    // latestRoot(tenant) == root
    let mut data = keccak(b"latestRoot(bytes32)")[..4].to_vec();
    data.extend_from_slice(&tenant);
    let result = rpc
        .eth_call(&contract_hex, &format!("0x{}", hex::encode(data)))
        .await
        .unwrap();
    assert_eq!(result.trim_start_matches("0x"), hex::encode(root));
}

/// Service-level cross-verification: a receipt must be provable against the on-chain root
/// that the broker itself submitted.
#[tokio::test]
async fn receipt_proof_cross_checks_the_chain_on_anvil() {
    // Distinct port: cargo runs tests in parallel and each test owns its anvil node.
    const PORT: u16 = 8556;
    use std::sync::Arc;

    use tessera_broker::anchoring::{AnchorTarget, AnchorTargetStore, MemoryAnchorTargetStore};
    use tessera_broker::authorize::{AuthorizeRequest, AuthorizeService};
    use tessera_broker::chain::MemoryChainStore;
    use tessera_broker::issuers::mock::MockIssuer;
    use tessera_broker::issuers::IssuerRegistry;
    use tessera_broker::policy::InMemoryPolicyStore;
    use tessera_broker::receipt::ReceiptSigner;

    if !anvil_available() {
        eprintln!("skipping: anvil not on PATH");
        return;
    }
    let Some(bytecode) = artifact_bytecode() else {
        eprintln!("skipping: ReceiptAnchor artifact not built (run `forge build`)");
        return;
    };

    let _child = KillOnDrop(
        Command::new("anvil")
            .args([
                "--port",
                &PORT.to_string(),
                "--chain-id",
                "31337",
                "--silent",
            ])
            .spawn()
            .expect("failed to spawn anvil"),
    );
    let url = format!("http://127.0.0.1:{PORT}");
    let rpc = RpcClient::new(&url);
    assert!(wait_for_node(&rpc).await, "anvil did not become ready");

    let signer = EthSigner::from_hex(DEV_PK).unwrap();
    let chain_id = rpc.chain_id().await.unwrap();
    let (deploy_hash, contract) = rpc.deploy(&signer, &bytecode, chain_id).await.unwrap();
    assert!(
        wait_for_tx(&rpc, &deploy_hash).await,
        "contract deploy failed"
    );
    let contract_hex = format!("0x{}", hex::encode(contract));

    let mut issuers = IssuerRegistry::new();
    issuers.register(Arc::new(MockIssuer::new("stripe")));
    let targets = MemoryAnchorTargetStore::new();
    targets
        .set(
            "acme",
            AnchorTarget {
                chain_id,
                rpc_url: url.clone(),
                contract: contract_hex.clone(),
                private_key: Some(DEV_PK.to_string()),
                signer_history: Vec::new(),
            },
        )
        .await
        .unwrap();

    let svc = AuthorizeService {
        policies: Arc::new(InMemoryPolicyStore::new()),
        issuers: Arc::new(issuers),
        authority: Default::default(),
        signer: Arc::new(
            ReceiptSigner::from_hex_or_random(
                Some("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
                31337,
                &contract_hex,
            )
            .unwrap(),
        ),
        chain: Arc::new(MemoryChainStore::new()),
        telemetry: Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        anchor: None,
        anchors: Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: Arc::new(targets),
        secrets: None,
        rpc_policy: Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
        agent_rate_limit_per_min: None,
        tool_rate_limits: Vec::new(),
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
        retention_days: 0,
        anchor_confirmations: 1,
        anchor_reorg_grace_secs: 0,
        revocations: Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http: reqwest::Client::new(),
        alert_acks: std::sync::Arc::new(tessera_broker::alert_acks::MemoryAlertAcks::new()),
        key_events: std::sync::Arc::new(tessera_broker::key_events::MemoryKeyEvents::new()),
        chain_checkpoints: std::sync::Arc::new(
            tessera_broker::chain_checkpoints::MemoryChainCheckpoints::new(),
        ),
        quota: std::sync::Arc::new(tessera_broker::quota::QuotaManager::disabled()),
        remediation_policies: std::sync::Arc::new(
            tessera_broker::remediation::MemoryRemediationPolicies::new(),
        ),
        tool_pins: std::sync::Arc::new(tessera_broker::tool_pins::MemoryToolPins::new()),
        alert_router: std::sync::Arc::new(tessera_broker::alerts::AlertRouter::new(
            std::sync::Arc::new(tessera_broker::alerts::MemoryAlertTargetStore::new()),
            None,
            None,
        )),
        key_expiry_alert_days: 0,
        key_rotation_max_age_hours: None,
        default_ttl_seconds: 30,
        demo_policy: Some(tessera_broker::policy::demo_policy()),
    };

    for amount in [1, 2, 3] {
        svc.authorize(
            "acme",
            AuthorizeRequest {
                agent_id: "agent-1".into(),
                user_id: "user-1".into(),
                tool: "stripe.refunds.create".into(),
                intent: "refund".into(),
                args: serde_json::json!({ "amount": amount }),
                tool_schema_hash: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    let record = svc
        .anchor_and_record("acme", "agent-1", false)
        .await
        .unwrap()
        .expect("anchor submitted");
    assert!(matches!(record.status.as_str(), "confirmed" | "submitted"));
    assert_eq!(
        record.chain_id, chain_id,
        "the anchor record must carry the tenant target's chain id, not the broker domain's"
    );

    let chain = svc.chain.chain("acme", "agent-1").await.unwrap();
    let proof = svc
        .receipt_proof("acme", "agent-1", Some(&chain[2].payload_hash), None)
        .await
        .unwrap();

    assert_eq!(proof["onchain"]["checked"], true, "proof={proof}");
    assert_eq!(proof["onchain"]["anchored"], true, "proof={proof}");
    assert!(
        proof["onchain"]["confirmations"].as_u64().unwrap() >= 1,
        "proof={proof}"
    );
    assert_eq!(proof["anchor"]["txHash"], record.tx_hash.unwrap());
}

/// The fee ceiling makes submission fail closed instead of paying a spike.
#[tokio::test]
async fn fee_cap_refuses_expensive_submissions() {
    if !anvil_available() {
        eprintln!("skipping: anvil not on PATH");
        return;
    }
    let Some(bytecode) = artifact_bytecode() else {
        eprintln!("skipping: ReceiptAnchor artifact not built (run `forge build`)");
        return;
    };

    const PORT: u16 = 8577;
    let _child = KillOnDrop(
        Command::new("anvil")
            .args([
                "--port",
                &PORT.to_string(),
                "--chain-id",
                "31337",
                "--silent",
            ])
            .spawn()
            .expect("failed to spawn anvil"),
    );
    let url = format!("http://127.0.0.1:{PORT}");
    let rpc = RpcClient::new(&url);
    assert!(wait_for_node(&rpc).await, "anvil did not become ready");

    let signer = EthSigner::from_hex(DEV_PK).unwrap();
    let chain_id = rpc.chain_id().await.unwrap();
    let (deploy_hash, contract) = rpc.deploy(&signer, &bytecode, chain_id).await.unwrap();
    assert!(wait_for_tx(&rpc, &deploy_hash).await, "deploy failed");
    let contract_hex = format!("0x{}", hex::encode(contract));

    // A 1-wei cap: any real fee exceeds it, so submission is refused. The cap is injected
    // rather than read from the environment so this test cannot race others.
    let strict = AnchorSubmitter::new(&url, DEV_PK, &contract_hex)
        .unwrap()
        .with_max_fee_per_gas(Some(1));
    assert_eq!(strict.max_fee_per_gas(), Some(1));
    let err = strict
        .submit(keccak(b"acme"), keccak(b"root"), 1)
        .await
        .expect_err("submission must be refused above the fee cap");
    assert!(
        err.to_string().contains("exceeds the configured cap"),
        "unexpected error: {err}"
    );

    // No cap (or a generous one): submission works as before.
    let open = AnchorSubmitter::new(&url, DEV_PK, &contract_hex)
        .unwrap()
        .with_max_fee_per_gas(None);
    assert_eq!(open.max_fee_per_gas(), None);
    let tx_hash = open
        .submit(keccak(b"acme"), keccak(b"root"), 1)
        .await
        .unwrap();
    assert!(open.wait_for_success(&tx_hash, 50).await.unwrap());
}
