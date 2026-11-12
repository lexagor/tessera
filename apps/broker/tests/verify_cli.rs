//! End-to-end test of the `tessera-verify` CLI against real exported bundles.

use std::process::Command;

use tessera_broker::authorize::{AuthorizeRequest, AuthorizeService, RecordRequest};
use tessera_broker::chain::MemoryChainStore;
use tessera_broker::issuers::mock::MockIssuer;
use tessera_broker::issuers::IssuerRegistry;
use tessera_broker::policy::InMemoryPolicyStore;
use tessera_broker::receipt::ReceiptSigner;

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

fn svc() -> std::sync::Arc<AuthorizeService> {
    let mut issuers = IssuerRegistry::new();
    issuers.register(std::sync::Arc::new(MockIssuer::new("stripe")));
    std::sync::Arc::new(AuthorizeService {
        policies: std::sync::Arc::new(InMemoryPolicyStore::new()),
        issuers: std::sync::Arc::new(issuers),
        authority: Default::default(),
        signer: std::sync::Arc::new(
            ReceiptSigner::from_hex_or_random(
                Some(TEST_KEY),
                84532,
                "0x0000000000000000000000000000000000000000",
            )
            .unwrap(),
        ),
        chain: std::sync::Arc::new(MemoryChainStore::new()),
        telemetry: std::sync::Arc::new(tessera_broker::telemetry::MemoryTelemetryStore::new()),
        anchor: None,
        anchors: std::sync::Arc::new(tessera_broker::anchoring::MemoryAnchorStore::new()),
        anchor_targets: std::sync::Arc::new(
            tessera_broker::anchoring::MemoryAnchorTargetStore::new(),
        ),
        secrets: None,
        rpc_policy: std::sync::Arc::new(tessera_broker::netguard::RpcPolicy::new(true, vec![])),
        egress: std::sync::Arc::new(tessera_broker::netguard::EgressGuard::permissive()),
        rate_limiter: std::sync::Arc::new(tessera_broker::ratelimit::MemoryRateLimiter::new()),
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
        gap_alerts: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
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
        key_expiry_alert_days: 7,
        key_rotation_max_age_hours: None,
        retention_days: 90,
        anchor_confirmations: 12,
        anchor_reorg_grace_secs: 300,
        revocations: std::sync::Arc::new(tessera_broker::revocation::MemoryRevocationStore::new()),
        http: reqwest::Client::new(),
        default_ttl_seconds: 30,
        demo_policy: Some(tessera_broker::policy::demo_policy()),
    })
}

async fn bundle_file() -> (tempfile_dir::TempDir, String) {
    let svc = svc();
    let request = AuthorizeRequest {
        agent_id: "agent-1".into(),
        user_id: "user-1".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund".into(),
        args: serde_json::json!({ "amount": 100 }),
        tool_schema_hash: None,
        ..Default::default()
    };
    let allowed = svc.authorize("acme", request).await.unwrap();
    svc.record(
        "acme",
        RecordRequest {
            agent_id: "agent-1".into(),
            receipt_id: allowed.receipt_id,
            result_hash: format!("0x{}", "dd".repeat(32)),
            status: Some("ok".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let bundle = svc.export_chain("acme", "agent-1").await.unwrap();
    let dir = tempfile_dir::TempDir::new();
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    let (dir, path) = (dir, path.to_string_lossy().to_string());
    (dir, path)
}

/// Minimal temp-dir helper (no extra dependency): creates and cleans up a directory.
mod tempfile_dir {
    /// Process-unique suffix for temp directories. `SystemTime` alone is not enough on
    /// platforms with coarse clock resolution (two threads can read the same value).
    fn unique_suffix() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        format!(
            "{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        )
    }

    pub struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        pub fn new() -> Self {
            let mut path = std::env::temp_dir();
            let unique = format!("tessera-verify-{}-{}", std::process::id(), {
                unique_suffix()
            });
            path.push(unique);
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tessera-verify"))
}

#[tokio::test]
async fn cli_accepts_a_valid_bundle() {
    let (_dir, path) = bundle_file().await;
    let output = cli().arg(&path).output().unwrap();
    assert!(
        output.status.success(),
        "expected success, stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("OK"));
    assert!(stdout.contains("tenant=acme"));
    assert!(stdout.contains("receipts=2"));
}

#[tokio::test]
async fn cli_rejects_a_tampered_bundle() {
    let (_dir, path) = bundle_file().await;
    let raw = std::fs::read_to_string(&path).unwrap();
    let mut bundle: tessera_broker::export::ExportBundle = serde_json::from_str(&raw).unwrap();
    bundle.receipts[0].payload_hash = format!("0x{}", "11".repeat(32));
    std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let output = cli().arg(&path).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("INVALID"));
}

#[tokio::test]
async fn cli_enforces_expected_signer() {
    let (_dir, path) = bundle_file().await;
    let signer = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

    let ok = cli()
        .args([path.as_str(), "--expect-signer", signer])
        .output()
        .unwrap();
    assert!(ok.status.success(), "signer should match the test key");

    let bad = cli()
        .args([
            path.as_str(),
            "--expect-signer",
            "0x000000000000000000000000000000000000dead",
        ])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("INVALID"));
}

#[tokio::test]
async fn cli_accepts_any_signer_from_a_rotation_history() {
    let (_dir, path) = bundle_file().await;
    // Simulates a delivered key history: one historical key plus the current one.
    let output = cli()
        .args([
            path.as_str(),
            "--expect-signer",
            "0x000000000000000000000000000000000000dead",
            "--expect-signer",
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "a receipt signed by any accepted key must verify"
    );
}

#[tokio::test]
async fn cli_verifies_tenant_wide_bundles() {
    let svc = svc();
    for agent in ["agent-a", "agent-b"] {
        let request = AuthorizeRequest {
            agent_id: agent.into(),
            user_id: "user-1".into(),
            tool: "stripe.refunds.create".into(),
            intent: "refund".into(),
            args: serde_json::json!({ "amount": 100 }),
            tool_schema_hash: None,
            ..Default::default()
        };
        svc.authorize("acme", request).await.unwrap();
    }
    let bundle = svc.export_tenant("acme").await.unwrap();
    assert!(bundle.verify().unwrap());

    let dir = tempfile_dir::TempDir::new();
    let path = dir.path().join("tenant.json");
    std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let output = cli().arg(path.to_str().unwrap()).output().unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("agents=2"));
    assert!(stdout.contains("receipts=2"));

    // Tampering with one agent bundle invalidates the aggregate.
    let mut tampered = bundle;
    tampered.agents[0].receipts[0].payload_hash = format!("0x{}", "44".repeat(32));
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let output = cli().arg(path.to_str().unwrap()).output().unwrap();
    assert!(!output.status.success());
}

#[tokio::test]
async fn cli_verifies_signed_limits_snapshots() {
    let svc = svc();
    let limits = svc.effective_limits("acme").await.unwrap();
    let snapshot = tessera_broker::export::sign_payload(
        &svc.signer,
        tessera_broker::export::LIMITS_DOMAIN,
        &limits,
    )
    .await
    .unwrap();
    let mut document = limits.clone();
    document
        .as_object_mut()
        .unwrap()
        .insert("snapshot".into(), serde_json::to_value(&snapshot).unwrap());

    let dir = tempfile_dir::TempDir::new();
    let path = dir.path().join("limits.json");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

    let output = cli()
        .args(["--limits", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("limits snapshot"));

    // Any change to the payload invalidates the snapshot.
    let mut tampered = document;
    tampered
        .as_object_mut()
        .unwrap()
        .insert("maxCredentialTtlSeconds".into(), serde_json::json!(999_999));
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let output = cli()
        .args(["--limits", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[tokio::test]
async fn tenant_archive_is_a_verifiable_self_describing_bundle() {
    let svc = svc();
    for agent in ["agent-a", "agent-b"] {
        let request = AuthorizeRequest {
            agent_id: agent.into(),
            user_id: "user-1".into(),
            tool: "stripe.refunds.create".into(),
            intent: "refund".into(),
            args: serde_json::json!({ "amount": 100 }),
            tool_schema_hash: None,
            ..Default::default()
        };
        svc.authorize("acme", request).await.unwrap();
    }
    let bundle = svc.export_tenant("acme").await.unwrap();
    let bytes =
        tessera_broker::export::build_tenant_archive(&bundle, "tessera-verify manifest.json")
            .unwrap();

    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    let mut names = Vec::new();
    let mut saw_readme = false;
    let mut manifest_agents = None;
    let mut verified_agents = 0;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().to_string();
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut content).unwrap();
        if name == "README.txt" {
            let text = String::from_utf8_lossy(&content);
            assert!(
                text.contains("tessera-verify"),
                "README must explain verification"
            );
            assert!(
                text.contains("tessera-export-v1"),
                "README must name the domain tag"
            );
            saw_readme = true;
        } else if name == "manifest.json" {
            let manifest: tessera_broker::export::TenantExportManifest =
                serde_json::from_slice(&content).unwrap();
            manifest_agents = Some(manifest.agent_count);
        } else if name.starts_with("agents/") {
            let agent: tessera_broker::export::ExportBundle =
                serde_json::from_slice(&content).unwrap();
            assert!(agent.verify().unwrap(), "{name} must verify standalone");
            verified_agents += 1;
        }
        names.push(name);
    }

    assert!(saw_readme);
    assert_eq!(manifest_agents, Some(2));
    assert_eq!(verified_agents, 2);
    assert!(names.contains(&"anchors.json".to_string()));
    assert!(names.contains(&"agents/agent-a.json".to_string()));
    assert!(names.contains(&"agents/agent-b.json".to_string()));
}

#[test]
fn keygen_derives_the_expected_address() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-keygen"))
        .args([
            "--address",
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );

    // Generating a key prints an address and a private key that round-trips.
    let generated = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-keygen"))
        .output()
        .unwrap();
    assert!(generated.status.success());
    let stdout = String::from_utf8_lossy(&generated.stdout);
    let key = stdout
        .lines()
        .find_map(|line| line.strip_prefix("private key: "))
        .expect("private key line");
    let derived = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-keygen"))
        .args(["--address", key])
        .output()
        .unwrap();
    let address = stdout
        .lines()
        .find_map(|line| line.strip_prefix("address:     "))
        .expect("address line");
    assert_eq!(String::from_utf8_lossy(&derived.stdout).trim(), address);
}

#[tokio::test]
async fn cli_verifies_an_extracted_archive_directory() {
    let svc = svc();
    for agent in ["agent-a", "agent-b"] {
        let request = AuthorizeRequest {
            agent_id: agent.into(),
            user_id: "user-1".into(),
            tool: "stripe.refunds.create".into(),
            intent: "refund".into(),
            args: serde_json::json!({ "amount": 100 }),
            tool_schema_hash: None,
            ..Default::default()
        };
        svc.authorize("acme", request).await.unwrap();
    }
    let bundle = svc.export_tenant("acme").await.unwrap();
    let bytes = tessera_broker::export::build_tenant_archive(&bundle, "tessera-verify --archive .")
        .unwrap();

    let dir = tempfile_dir::TempDir::new();
    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(dir.path()).unwrap();
    assert!(dir.path().join("README.txt").exists());

    let output = cli()
        .args(["--archive", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("archive tenant=acme"));

    // The README's suggested command is the one that works.
    let readme = std::fs::read_to_string(dir.path().join("README.txt")).unwrap();
    assert!(
        readme.contains("--archive ."),
        "README must show the working command"
    );

    // Tampering with one agent file invalidates the archive.
    let agent_path = dir.path().join("agents/agent-a.json");
    let mut agent: tessera_broker::export::ExportBundle =
        serde_json::from_str(&std::fs::read_to_string(&agent_path).unwrap()).unwrap();
    agent.receipts[0].payload_hash = format!("0x{}", "55".repeat(32));
    std::fs::write(&agent_path, serde_json::to_vec(&agent).unwrap()).unwrap();
    let output = cli()
        .args(["--archive", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("INVALID"));
}

#[tokio::test]
async fn archive_index_records_every_archive_and_detects_rewrites() {
    let svc = svc();
    let mut request = AuthorizeRequest {
        agent_id: "agent-a".into(),
        user_id: "user-1".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund".into(),
        args: serde_json::json!({ "amount": 100 }),
        tool_schema_hash: None,
        ..Default::default()
    };
    svc.authorize("acme", request.clone()).await.unwrap();

    let dir = tempfile_dir::TempDir::new();
    // Two archives: the index must accumulate one signed entry per write.
    let first = svc
        .write_tenant_archive("acme", dir.path())
        .await
        .unwrap()
        .unwrap();
    request.args = serde_json::json!({ "amount": 200 });
    svc.authorize("acme", request).await.unwrap();
    let second = svc
        .write_tenant_archive("acme", dir.path())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(first, second);

    let index = dir.path().join(tessera_broker::export::ARCHIVE_INDEX_FILE);
    let lines: Vec<_> = std::fs::read_to_string(&index)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 2, "one entry per archive write");

    let output = cli()
        .args(["--archive-index", index.to_str().unwrap(), "--check-files"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("entries=2"));

    // Rewriting an archive after the fact is detected by the digest check.
    let tampered = second.clone();
    let mut bytes = std::fs::read(&tampered).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&tampered, bytes).unwrap();
    let output = cli()
        .args(["--archive-index", index.to_str().unwrap(), "--check-files"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rewritten"));

    // Tampering with an index line invalidates its signature.
    let mut lines = lines;
    let mut entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    entry
        .as_object_mut()
        .unwrap()
        .insert("bytes".into(), serde_json::json!(1));
    lines[0] = entry.to_string();
    std::fs::write(&index, format!("{}\n", lines.join("\n"))).unwrap();
    let output = cli()
        .args(["--archive-index", index.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signature"));
}

#[tokio::test]
async fn restore_drill_rebuilds_chains_from_evidence() {
    let svc = svc();
    for agent in ["agent-a", "agent-b"] {
        let request = AuthorizeRequest {
            agent_id: agent.into(),
            user_id: "user-1".into(),
            tool: "stripe.refunds.create".into(),
            intent: "refund".into(),
            args: serde_json::json!({ "amount": 100 }),
            tool_schema_hash: None,
            ..Default::default()
        };
        svc.authorize("acme", request).await.unwrap();
    }
    let original = svc.export_tenant("acme").await.unwrap();
    let bytes =
        tessera_broker::export::build_tenant_archive(&original, "tessera-verify --archive .")
            .unwrap();

    let archive_dir = tempfile_dir::TempDir::new();
    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(archive_dir.path()).unwrap();

    let out_dir = tempfile_dir::TempDir::new();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-restore"))
        .args([
            archive_dir.path().to_str().unwrap(),
            "--out",
            out_dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("RESTORED"));

    // Each agent chain is rebuilt, in order, with the same payload hashes as the source.
    let mut restored_hashes = Vec::new();
    for agent in ["agent-a", "agent-b"] {
        let path = out_dir.path().join(format!("chain-{agent}.jsonl"));
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let expected = original
            .agents
            .iter()
            .find(|bundle| bundle.manifest.agent == agent)
            .unwrap();
        assert_eq!(lines.len(), expected.receipts.len());
        for (line, entry) in lines.iter().zip(expected.receipts.iter()) {
            assert_eq!(line["payloadHash"], entry.payload_hash);
        }
        restored_hashes.push(lines.len());
    }
    assert_eq!(restored_hashes, vec![1, 1]);

    let summary: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out_dir.path().join("restore.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(summary["verified"], true);
    assert_eq!(summary["agentCount"], 2);
    assert_eq!(summary["merkleRoot"], original.manifest.merkle_root);

    // A tampered archive is refused and nothing is written.
    let bad_dir = tempfile_dir::TempDir::new();
    let bad_out = tempfile_dir::TempDir::new();
    {
        let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(bad_dir.path()).unwrap();
    }
    let agent_path = bad_dir.path().join("agents/agent-a.json");
    let raw = std::fs::read_to_string(&agent_path).unwrap();
    let mut agent: tessera_broker::export::ExportBundle = serde_json::from_str(&raw).unwrap();
    agent.receipts[0].payload_hash = format!("0x{}", "66".repeat(32));
    std::fs::write(&agent_path, serde_json::to_vec(&agent).unwrap()).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-restore"))
        .args([
            bad_dir.path().to_str().unwrap(),
            "--out",
            bad_out.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("verification"));
    assert_eq!(
        std::fs::read_dir(bad_out.path()).unwrap().count(),
        0,
        "nothing may be written from an unverified archive"
    );

    // A rotation-history expectation that cannot match is refused up front.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-restore"))
        .args([
            archive_dir.path().to_str().unwrap(),
            "--out",
            out_dir.path().to_str().unwrap(),
            "--expect-signer",
            "0x000000000000000000000000000000000000dead",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[tokio::test]
async fn cli_verifies_archives_carrying_ledger_and_checkpoints() {
    let svc = svc();
    let request = AuthorizeRequest {
        agent_id: "agent-a".into(),
        user_id: "user-1".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund".into(),
        args: serde_json::json!({ "amount": 100 }),
        tool_schema_hash: None,
        ..Default::default()
    };
    svc.authorize("acme", request.clone()).await.unwrap();
    svc.append_key_event(
        "acme",
        "key.created",
        &{
            let mut record = tessera_broker::auth::new_record("acme", "ci", "tsk_x");
            record.id = "key_1".into();
            record
        },
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let dir = tempfile_dir::TempDir::new();
    svc.write_tenant_archive("acme", dir.path())
        .await
        .unwrap()
        .unwrap();
    let archive_path = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().map(|e| e == "gz").unwrap_or(false))
        .expect("archive written");

    let extract = tempfile_dir::TempDir::new();
    let decoder = flate2::read::GzDecoder::new(std::fs::File::open(&archive_path).unwrap());
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(extract.path()).unwrap();
    assert!(extract.path().join("key-events.json").exists());
    assert!(extract.path().join("checkpoints.json").exists());

    let output = cli()
        .args(["--archive", extract.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "archive with ledger/checkpoints must verify: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Tampering with the ledger file invalidates the archive.
    let events_path = extract.path().join("key-events.json");
    let raw = std::fs::read_to_string(&events_path).unwrap();
    let mut events: serde_json::Value = serde_json::from_str(&raw).unwrap();
    events[0]["kind"] = serde_json::json!("key.tampered");
    std::fs::write(&events_path, serde_json::to_vec(&events).unwrap()).unwrap();
    let output = cli()
        .args(["--archive", extract.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("INVALID"));
}

#[tokio::test]
async fn restore_attestation_round_trips_and_detects_tampering() {
    // Two independent brokers: the source that produced the chain, and the target that
    // imports it (each `svc()` call builds a fresh in-memory stack).
    let source = svc();
    let target = svc();
    let request = AuthorizeRequest {
        agent_id: "agent-a".into(),
        user_id: "user-1".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund".into(),
        args: serde_json::json!({ "amount": 100 }),
        tool_schema_hash: None,
        ..Default::default()
    };
    source.authorize("acme", request).await.unwrap();

    // Broker-side attestation on import.
    let bundle = source.export_chain("acme", "agent-a").await.unwrap();
    let imported = target.import_chain("acme", &bundle).await.unwrap();
    let certificate = imported["attestation"]["certificate"].clone();
    let snapshot: tessera_broker::export::SignedPayload =
        serde_json::from_value(imported["attestation"]["snapshot"].clone()).unwrap();
    assert_eq!(certificate["imported"], 1);
    assert!(tessera_broker::export::verify_signed_payload(
        tessera_broker::export::RESTORE_DOMAIN,
        &certificate,
        &snapshot,
        &target.accepted_signers(),
    )
    .unwrap());

    // Operator-side attestation from the restore CLI.
    use tessera_broker::export::build_tenant_archive;
    let tenant_bundle = source.export_tenant("acme").await.unwrap();
    let bytes = build_tenant_archive(&tenant_bundle, "tessera-verify --archive .").unwrap();
    let archive_dir = tempfile_dir::TempDir::new();
    let decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(archive_dir.path()).unwrap();

    let out_dir = tempfile_dir::TempDir::new();
    let attest_path = out_dir.path().join("restore-attestation.json");
    let operator_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-restore"))
        .args([
            archive_dir.path().to_str().unwrap(),
            "--out",
            out_dir.path().to_str().unwrap(),
            "--attest",
            attest_path.to_str().unwrap(),
            "--signing-key",
            operator_key,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ATTESTED"));

    // Verify the attestation offline, with the expected operator address.
    let operator = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    let verified = cli()
        .args([
            "--attestation",
            attest_path.to_str().unwrap(),
            "--expect-signer",
            operator,
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("OK  restore attestation"));

    // Wrong expected signer is rejected.
    let wrong = cli()
        .args([
            "--attestation",
            attest_path.to_str().unwrap(),
            "--expect-signer",
            "0x000000000000000000000000000000000000dead",
        ])
        .output()
        .unwrap();
    assert!(!wrong.status.success());

    // Tampering with the certificate invalidates the attestation.
    let raw = std::fs::read_to_string(&attest_path).unwrap();
    let mut document: serde_json::Value = serde_json::from_str(&raw).unwrap();
    document["certificate"]["receiptCount"] = serde_json::json!(9999);
    std::fs::write(&attest_path, serde_json::to_vec(&document).unwrap()).unwrap();
    let tampered = cli()
        .args(["--attestation", attest_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!tampered.status.success());

    // --attest without a signing key fails loudly.
    let missing_key = std::process::Command::new(env!("CARGO_BIN_EXE_tessera-restore"))
        .args([
            archive_dir.path().to_str().unwrap(),
            "--out",
            out_dir.path().to_str().unwrap(),
            "--attest",
            out_dir.path().join("x.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!missing_key.status.success());
}

#[tokio::test]
async fn archive_index_tolerates_retention_pruning() {
    let svc = svc();
    let request = AuthorizeRequest {
        agent_id: "agent-a".into(),
        user_id: "user-1".into(),
        tool: "stripe.refunds.create".into(),
        intent: "refund".into(),
        args: serde_json::json!({ "amount": 100 }),
        tool_schema_hash: None,
        ..Default::default()
    };
    svc.authorize("acme", request).await.unwrap();

    let dir = tempfile_dir::TempDir::new();
    // Old archive + snapshot, then a fresh pair so the old ones are prunable.
    std::fs::write(
        dir.path()
            .join("tessera-export-acme-20200101T000000Z-aaaaaaaa.tar.gz"),
        b"old",
    )
    .unwrap();
    svc.write_tenant_archive("acme", dir.path())
        .await
        .unwrap()
        .unwrap();
    let report = svc.integrity_report("acme").await.unwrap();
    svc.write_signed_snapshot(dir.path(), "integrity", "acme", report)
        .await
        .unwrap();

    // Simulate retention removing the *indexed* archive (deterministically: take the file
    // name from the index itself, not from directory order).
    let index = dir.path().join(tessera_broker::export::ARCHIVE_INDEX_FILE);
    let first_entry: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&index)
            .unwrap()
            .lines()
            .next()
            .expect("archive index entry"),
    )
    .unwrap();
    let removed = first_entry["file"].as_str().unwrap().to_string();
    std::fs::remove_file(dir.path().join(&removed)).unwrap();
    let pruned_entry = {
        let entry = serde_json::json!({
            "kind": "retention.pruned",
            "prunedAt": "2026-09-17T00:00:00Z",
            "retentionDays": 1,
            "files": [removed],
        });
        let snapshot = tessera_broker::export::sign_payload(
            &svc.signer,
            tessera_broker::export::ARCHIVE_INDEX_DOMAIN,
            &entry,
        )
        .await
        .unwrap();
        let mut line = entry;
        line.as_object_mut()
            .unwrap()
            .insert("snapshot".into(), serde_json::to_value(snapshot).unwrap());
        line
    };
    let mut body = std::fs::read_to_string(&index).unwrap();
    body.push_str(&pruned_entry.to_string());
    body.push('\n');
    std::fs::write(&index, body).unwrap();

    // The index verifies: the pruned file is reported as pruned, not as missing.
    let output = cli()
        .args(["--archive-index", index.to_str().unwrap(), "--check-files"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("pruned=1"));

    // Without the retention entry covering it, a missing file still fails.
    let mut lines: Vec<String> = std::fs::read_to_string(&index)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    lines.pop();
    std::fs::write(&index, format!("{}\n", lines.join("\n"))).unwrap();
    let output = cli()
        .args(["--archive-index", index.to_str().unwrap(), "--check-files"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
