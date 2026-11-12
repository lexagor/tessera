//! `tessera-restore` — rebuild chain state from a signed evidence archive.
//!
//! Usage:
//!   tessera-restore <archive-dir> [--out <dir>] [--expect-signer 0x…]…
//!
//! The archive is verified in full before anything is written. On success it emits one
//! JSONL file per agent (`chain-<agent>.jsonl`, oldest receipt first) plus `restore.json`
//! describing what was recovered. This is the disaster-recovery drill: the broker database
//! can be lost, and the chain (with its signatures and Merkle roots) can be rebuilt from the
//! evidence store alone.
//!
//! Exit codes: 0 = restored, 1 = invalid archive or write failure, 2 = usage error.

use std::path::Path;
use std::process::ExitCode;

use tessera_broker::export::{ExportBundle, TenantExportBundle, TenantExportManifest};

struct Args {
    archive: String,
    out: Option<String>,
    expect_signers: Vec<String>,
    attest: Option<String>,
    signing_key: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut archive = None;
    let mut out = None;
    let mut expect_signers = Vec::new();
    let mut attest = None;
    let mut signing_key = None;
    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: tessera-restore <archive-dir> [--out <dir>] [--expect-signer 0x…]…\n       \
                     tessera-restore <archive-dir> --attest <file> --signing-key 0x…"
                );
                return Err(String::new());
            }
            "--out" => {
                index += 1;
                out = Some(raw.get(index).ok_or("--out needs a directory")?.clone());
            }
            "--expect-signer" => {
                index += 1;
                expect_signers.push(
                    raw.get(index)
                        .ok_or("--expect-signer needs an address")?
                        .clone(),
                );
            }
            "--attest" => {
                index += 1;
                attest = Some(
                    raw.get(index)
                        .ok_or("--attest needs an output path")?
                        .clone(),
                );
            }
            "--signing-key" => {
                index += 1;
                signing_key = Some(
                    raw.get(index)
                        .ok_or("--signing-key needs a 32-byte hex key")?
                        .clone(),
                );
            }
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => {
                if archive.is_some() {
                    return Err("only one archive directory may be given".into());
                }
                archive = Some(other.to_string());
            }
        }
        index += 1;
    }
    Ok(Args {
        archive: archive.ok_or("no archive directory given")?,
        out,
        expect_signers,
        attest,
        signing_key,
    })
}

fn load_bundle(dir: &Path) -> Result<TenantExportBundle, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest: TenantExportManifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?,
    )
    .map_err(|e| format!("invalid manifest.json: {e}"))?;

    let agents_dir = dir.join("agents");
    let mut files: Vec<_> = std::fs::read_dir(&agents_dir)
        .map_err(|e| format!("cannot read {}: {e}", agents_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|e| e == "json").unwrap_or(false))
        .collect();
    files.sort();

    let mut agents = Vec::with_capacity(files.len());
    for path in files {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        agents.push(
            serde_json::from_str::<ExportBundle>(&raw)
                .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        );
    }

    let anchors = match std::fs::read_to_string(dir.join("anchors.json")) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("invalid anchors.json: {e}"))?,
        Err(_) => Vec::new(),
    };
    let key_events = match std::fs::read_to_string(dir.join("key-events.json")) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| format!("invalid key-events.json: {e}"))?
        }
        Err(_) => Vec::new(),
    };
    let checkpoints = match std::fs::read_to_string(dir.join("checkpoints.json")) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| format!("invalid checkpoints.json: {e}"))?
        }
        Err(_) => Vec::new(),
    };
    let policies = match std::fs::read_to_string(dir.join("policies.json")) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("invalid policies.json: {e}"))?,
        Err(_) => Vec::new(),
    };

    Ok(TenantExportBundle {
        manifest,
        agents,
        anchors,
        key_events,
        checkpoints,
        policies,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("error: {message}");
            }
            return ExitCode::from(2);
        }
    };

    let archive = Path::new(&args.archive);
    let bundle = match load_bundle(archive) {
        Ok(bundle) => bundle,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::FAILURE;
        }
    };

    // Verify everything before writing anything: a restore must never ingest unverified data.
    if !args.expect_signers.is_empty()
        && !args
            .expect_signers
            .iter()
            .any(|expected| bundle.manifest.signer.eq_ignore_ascii_case(expected))
    {
        eprintln!(
            "error: archive was signed by {} which is not in the accepted signer set",
            bundle.manifest.signer
        );
        return ExitCode::FAILURE;
    }
    match bundle.verify() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("error: archive failed verification (linkage, Merkle root, or signature)");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("error: archive verification failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    let out_dir = Path::new(args.out.as_deref().unwrap_or("."));
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        eprintln!("error: cannot create {}: {e}", out_dir.display());
        return ExitCode::FAILURE;
    }

    let mut restored = 0usize;
    let mut receipts = 0u64;
    for agent in &bundle.agents {
        let name = agent.manifest.agent.clone();
        // Never let an archive's agent id escape the output directory.
        let safe_name = tessera_broker::auth::safe_agent_filename(&name);
        let path = out_dir.join(format!("chain-{safe_name}.jsonl"));
        let mut body = String::new();
        for entry in &agent.receipts {
            let line = serde_json::json!({
                "payloadHash": entry.payload_hash,
                "receipt": entry.receipt,
            });
            body.push_str(&line.to_string());
            body.push('\n');
        }
        if let Err(e) = std::fs::write(&path, body) {
            eprintln!("error: cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        restored += 1;
        receipts += agent.manifest.receipt_count;
        println!(
            "restored agent={name} receipts={} head={} -> {}",
            agent.manifest.receipt_count,
            agent.manifest.head.as_deref().unwrap_or("(empty)"),
            path.display()
        );
    }

    let summary = serde_json::json!({
        "tenant": bundle.manifest.tenant,
        "restoredAt": chrono::Utc::now().to_rfc3339(),
        "agentCount": bundle.manifest.agent_count,
        "receiptCount": receipts,
        "merkleRoot": bundle.manifest.merkle_root,
        "brokerSigner": bundle.manifest.signer,
        "tenantSigner": bundle.manifest.tenant_signer,
        "anchors": bundle.anchors.len(),
        "verified": true,
        "truncated": bundle.manifest.truncated,
    });
    let summary_path = out_dir.join("restore.json");
    if let Err(e) = std::fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summary).unwrap_or_default(),
    ) {
        eprintln!("error: cannot write {}: {e}", summary_path.display());
        return ExitCode::FAILURE;
    }

    // Optional operator attestation: a signed certificate of the restore operation.
    if let Some(path) = &args.attest {
        let Some(key) = args.signing_key.as_deref() else {
            eprintln!("error: --attest requires --signing-key (the operator's key)");
            return ExitCode::FAILURE;
        };
        let signer: std::sync::Arc<dyn tessera_broker::signer::DigestSigner> =
            match tessera_broker::signer::LocalSigner::from_hex(key) {
                Ok(signer) => std::sync::Arc::new(signer),
                Err(e) => {
                    eprintln!("error: bad --signing-key: {e}");
                    return ExitCode::FAILURE;
                }
            };
        let certificate = serde_json::json!({
            "tenant": bundle.manifest.tenant,
            "restoredAt": chrono::Utc::now().to_rfc3339(),
            "agentCount": restored,
            "receiptCount": receipts,
            "merkleRoot": bundle.manifest.merkle_root,
            "brokerSigner": bundle.manifest.signer,
            "tenantSigner": bundle.manifest.tenant_signer,
            "operator": tessera_broker::signer::DigestSigner::address_hex(signer.as_ref()),
            "truncated": bundle.manifest.truncated,
        });
        let digest = match tessera_broker::export::payload_digest(
            tessera_broker::export::RESTORE_DOMAIN,
            &certificate,
        ) {
            Ok(digest) => digest,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        let signature = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|runtime| {
                runtime
                    .block_on(tessera_broker::signer::DigestSigner::sign_prehash(
                        signer.as_ref(),
                        &digest,
                    ))
                    .map_err(|e| e.to_string())
            }) {
            Ok((r, s, recid)) => {
                let mut out = Vec::with_capacity(65);
                out.extend_from_slice(&r);
                out.extend_from_slice(&s);
                out.push(recid + 27);
                format!("0x{}", hex::encode(out))
            }
            Err(e) => {
                eprintln!("error: signing failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        let document = serde_json::json!({
            "certificate": certificate,
            "snapshot": {
                "domain": tessera_broker::export::RESTORE_DOMAIN,
                "digest": format!("0x{}", hex::encode(digest)),
                "signer": tessera_broker::signer::DigestSigner::address_hex(signer.as_ref()),
                "signature": signature,
                "signedAt": chrono::Utc::now().to_rfc3339(),
            },
        });
        if let Err(e) = std::fs::write(
            path,
            serde_json::to_vec_pretty(&document).unwrap_or_default(),
        ) {
            eprintln!("error: cannot write attestation {path}: {e}");
            return ExitCode::FAILURE;
        }
        println!(
            "ATTESTED by {} -> {path}",
            tessera_broker::signer::DigestSigner::address_hex(signer.as_ref())
        );
    }

    println!(
        "RESTORED tenant={} agents={} receipts={} anchors={} -> {}",
        bundle.manifest.tenant,
        restored,
        receipts,
        bundle.anchors.len(),
        summary_path.display()
    );
    if bundle.manifest.truncated {
        println!(
            "note: the archive was truncated; recover the remaining receipts from earlier archives"
        );
    }
    ExitCode::SUCCESS
}
