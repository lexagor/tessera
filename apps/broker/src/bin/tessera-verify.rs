//! `tessera-verify` — verify signed Tessera artifacts offline.
//!
//! Usage:
//!   tessera-verify <bundle.json> [--expect-signer 0x…]… [--expect-tenant-signer 0x…]…
//!   tessera-verify --limits <snapshot.json> [--expect-signer 0x…]…
//!
//! Accepts single-agent export bundles, tenant-wide export bundles, and signed limits
//! snapshots (`GET /v1/limits?sign=true`). Exit codes: 0 = valid, 1 = invalid/unreadable,
//! 2 = usage error.

use std::process::ExitCode;

use tessera_broker::export::{ExportBundle, SignedPayload, TenantExportBundle};

struct Args {
    path: Option<String>,
    limits: Option<String>,
    archive: Option<String>,
    archive_index: Option<String>,
    attestation: Option<String>,
    check_files: bool,
    expect_signers: Vec<String>,
    expect_tenant_signers: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        path: None,
        limits: None,
        archive: None,
        archive_index: None,
        attestation: None,
        check_files: false,
        expect_signers: Vec::new(),
        expect_tenant_signers: Vec::new(),
    };
    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: tessera-verify <bundle.json> [--expect-signer 0x…]… \
                     [--expect-tenant-signer 0x…]…\n       \
                     tessera-verify --archive <extracted-dir> [--expect-signer 0x…]…\n       \
                     tessera-verify --limits <snapshot.json> [--expect-signer 0x…]…"
                );
                return Err(String::new());
            }
            "--expect-signer" => {
                index += 1;
                let value = raw.get(index).ok_or("--expect-signer needs an address")?;
                args.expect_signers.push(value.clone());
            }
            "--expect-tenant-signer" => {
                index += 1;
                let value = raw
                    .get(index)
                    .ok_or("--expect-tenant-signer needs an address")?;
                args.expect_tenant_signers.push(value.clone());
            }
            "--limits" => {
                index += 1;
                let value = raw.get(index).ok_or("--limits needs a file path")?;
                args.limits = Some(value.clone());
            }
            "--archive" => {
                index += 1;
                let value = raw.get(index).ok_or("--archive needs a directory path")?;
                args.archive = Some(value.clone());
            }
            "--archive-index" => {
                index += 1;
                let value = raw.get(index).ok_or("--archive-index needs a path")?;
                args.archive_index = Some(value.clone());
            }
            "--check-files" => args.check_files = true,
            "--attestation" => {
                index += 1;
                let value = raw.get(index).ok_or("--attestation needs a file path")?;
                args.attestation = Some(value.clone());
            }
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => {
                if args.path.is_some() {
                    return Err("only one bundle path may be given".into());
                }
                args.path = Some(other.to_string());
            }
        }
        index += 1;
    }
    if args.path.is_none()
        && args.limits.is_none()
        && args.archive.is_none()
        && args.archive_index.is_none()
        && args.attestation.is_none()
    {
        return Err("no input file given".into());
    }
    Ok(args)
}

fn read_json(path: &str) -> Result<serde_json::Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{path} is not valid JSON: {e}"))
}

fn signer_ok(actual: &str, expected: &[String]) -> bool {
    expected.is_empty() || expected.iter().any(|e| actual.eq_ignore_ascii_case(e))
}

fn verify_bundle_file(path: &str, args: &Args) -> Result<(), String> {
    let value = read_json(path)?;
    if value.get("agents").is_some() {
        let bundle: TenantExportBundle = serde_json::from_value(value)
            .map_err(|e| format!("{path} is not a valid tenant export bundle: {e}"))?;
        let manifest = &bundle.manifest;
        if !signer_ok(&manifest.signer, &args.expect_signers) {
            return Err(format!(
                "broker signer is {} but a different key was expected",
                manifest.signer
            ));
        }
        if let Some(expected) = args.expect_tenant_signers.first() {
            match manifest.tenant_signer.as_deref() {
                Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
                Some(actual) => {
                    return Err(format!(
                        "tenant signer is {actual} but {expected} was expected"
                    ))
                }
                None => return Err("bundle has no tenant signature".into()),
            }
        }
        return if bundle.verify().map_err(|e| e.to_string())? {
            println!(
                "OK  tenant={} agents={} receipts={} merkleRoot={} broker={}{}",
                manifest.tenant,
                manifest.agent_count,
                manifest.receipt_count,
                manifest.merkle_root,
                manifest.signer,
                match &manifest.tenant_signer {
                    Some(tenant) => format!(" tenant={tenant}"),
                    None => String::new(),
                }
            );
            if manifest.truncated {
                println!("note: tenant export is truncated (agent/receipt caps reached)");
            }
            Ok(())
        } else {
            Err("aggregate linkage, Merkle root, or signature check failed".into())
        };
    }

    let bundle: ExportBundle = serde_json::from_value(value)
        .map_err(|e| format!("{path} is not a valid export bundle: {e}"))?;
    let manifest = &bundle.manifest;
    if !signer_ok(&manifest.signer, &args.expect_signers) {
        return Err(format!(
            "broker signer is {} but a different key was expected",
            manifest.signer
        ));
    }
    if let Some(expected) = args.expect_tenant_signers.first() {
        match manifest.tenant_signer.as_deref() {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Some(actual) => {
                return Err(format!(
                    "tenant signer is {actual} but {expected} was expected"
                ))
            }
            None => return Err("bundle has no tenant signature".into()),
        }
    }
    if !bundle.verify().map_err(|e| e.to_string())? {
        return Err("linkage, Merkle root, or signature check failed".into());
    }
    println!(
        "OK  tenant={} agent={} receipts={} chainLength={} head={} merkleRoot={} broker={}{}",
        manifest.tenant,
        manifest.agent,
        manifest.receipt_count,
        manifest.chain_length,
        manifest.head.as_deref().unwrap_or("(empty)"),
        manifest.merkle_root,
        manifest.signer,
        match &manifest.tenant_signer {
            Some(tenant) => format!(" tenant={tenant}"),
            None => String::new(),
        }
    );
    if manifest.truncated {
        println!(
            "note: bundle is truncated (chain length {} > exported {})",
            manifest.chain_length, manifest.receipt_count
        );
    }
    Ok(())
}

fn verify_limits_snapshot(path: &str, args: &Args) -> Result<(), String> {
    let mut value = read_json(path)?;
    let snapshot_value = value
        .get("snapshot")
        .cloned()
        .ok_or("limits snapshot has no `snapshot` field")?;
    let snapshot: SignedPayload =
        serde_json::from_value(snapshot_value).map_err(|e| format!("invalid snapshot: {e}"))?;
    if let Some(object) = value.as_object_mut() {
        object.remove("snapshot");
    }
    if !signer_ok(&snapshot.signer, &args.expect_signers) {
        return Err(format!(
            "snapshot signer is {} but a different key was expected",
            snapshot.signer
        ));
    }
    let valid = tessera_broker::export::verify_signed_payload(
        tessera_broker::export::LIMITS_DOMAIN,
        &value,
        &snapshot,
        &args.expect_signers,
    )
    .map_err(|e| e.to_string())?;
    if !valid {
        return Err("snapshot digest or signature check failed".into());
    }
    println!(
        "OK  limits snapshot tenant={} signedAt={} digest={} broker={}",
        value
            .get("tenant")
            .and_then(|t| t.as_str())
            .unwrap_or("(unknown)"),
        snapshot.signed_at,
        snapshot.digest,
        snapshot.signer
    );
    Ok(())
}

/// Verify an extracted tenant archive directory (README.txt + manifest.json +
/// agents/*.json + anchors.json).
fn verify_archive_dir(dir: &str, args: &Args) -> Result<(), String> {
    let root = std::path::Path::new(dir);
    let manifest_path = root.join("manifest.json");
    let manifest_raw = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
    let manifest: tessera_broker::export::TenantExportManifest =
        serde_json::from_str(&manifest_raw).map_err(|e| format!("invalid manifest.json: {e}"))?;

    let agents_dir = root.join("agents");
    let mut entries: Vec<_> = std::fs::read_dir(&agents_dir)
        .map_err(|e| format!("cannot read {}: {e}", agents_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|e| e == "json").unwrap_or(false))
        .collect();
    entries.sort();
    let mut agents = Vec::with_capacity(entries.len());
    for path in entries {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        agents.push(
            serde_json::from_str::<tessera_broker::export::ExportBundle>(&raw)
                .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        );
    }

    let anchors = match std::fs::read_to_string(root.join("anchors.json")) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("invalid anchors.json: {e}"))?,
        Err(_) => Vec::new(),
    };
    let key_events = match std::fs::read_to_string(root.join("key-events.json")) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| format!("invalid key-events.json: {e}"))?
        }
        Err(_) => Vec::new(),
    };
    let checkpoints = match std::fs::read_to_string(root.join("checkpoints.json")) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| format!("invalid checkpoints.json: {e}"))?
        }
        Err(_) => Vec::new(),
    };
    let policies = match std::fs::read_to_string(root.join("policies.json")) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("invalid policies.json: {e}"))?,
        Err(_) => Vec::new(),
    };

    if !signer_ok(&manifest.signer, &args.expect_signers) {
        return Err(format!(
            "broker signer is {} but a different key was expected",
            manifest.signer
        ));
    }
    if let Some(expected) = args.expect_tenant_signers.first() {
        match manifest.tenant_signer.as_deref() {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Some(actual) => {
                return Err(format!(
                    "tenant signer is {actual} but {expected} was expected"
                ))
            }
            None => return Err("archive has no tenant signature".into()),
        }
    }

    let bundle = tessera_broker::export::TenantExportBundle {
        manifest,
        agents,
        anchors,
        key_events,
        checkpoints,
        policies,
    };
    if !bundle.verify().map_err(|e| e.to_string())? {
        return Err("aggregate linkage, Merkle root, or signature check failed".into());
    }
    println!(
        "OK  archive tenant={} agents={} receipts={} merkleRoot={} broker={}{}",
        bundle.manifest.tenant,
        bundle.manifest.agent_count,
        bundle.manifest.receipt_count,
        bundle.manifest.merkle_root,
        bundle.manifest.signer,
        match &bundle.manifest.tenant_signer {
            Some(tenant) => format!(" tenant={tenant}"),
            None => String::new(),
        }
    );
    Ok(())
}

/// Verify an archive index (`INDEX.jsonl`): every line is a signed entry; optionally
/// re-check each referenced archive's digest on disk.
fn verify_archive_index(path: &str, args: &Args) -> Result<(), String> {
    let root = std::path::Path::new(path);
    let file = if root.is_dir() {
        root.join(tessera_broker::export::ARCHIVE_INDEX_FILE)
    } else {
        root.to_path_buf()
    };
    let raw = std::fs::read_to_string(&file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let dir = file
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    // Files pruned by retention policy are expected to be absent.
    let mut pruned: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if value["kind"] == "retention.pruned" {
                if let Some(files) = value["files"].as_array() {
                    for file in files.iter().filter_map(|f| f.as_str()) {
                        pruned.insert(file.to_string());
                    }
                }
            }
        }
    }

    let mut entries = 0usize;
    let mut pruned_seen = 0usize;
    let mut total_bytes = 0u64;
    for (line_no, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("line {}: invalid JSON: {e}", line_no + 1))?;
        let snapshot_value = value
            .get("snapshot")
            .cloned()
            .ok_or_else(|| format!("line {}: missing snapshot", line_no + 1))?;
        let snapshot: SignedPayload = serde_json::from_value(snapshot_value)
            .map_err(|e| format!("line {}: invalid snapshot: {e}", line_no + 1))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("snapshot");
        }
        if !signer_ok(&snapshot.signer, &args.expect_signers) {
            return Err(format!(
                "line {}: signer is {} but a different key was expected",
                line_no + 1,
                snapshot.signer
            ));
        }
        if !tessera_broker::export::verify_signed_payload(
            tessera_broker::export::ARCHIVE_INDEX_DOMAIN,
            &value,
            &snapshot,
            &args.expect_signers,
        )
        .map_err(|e| e.to_string())?
        {
            return Err(format!(
                "line {}: signature or digest check failed",
                line_no + 1
            ));
        }

        if args.check_files {
            // Metadata-only entries (retention records) carry no file to hash.
            let Some(name) = value.get("file").and_then(|f| f.as_str()) else {
                entries += 1;
                continue;
            };
            let archive_path = dir.join(name);
            // Retention-pruned files are expected to be gone: count and move on.
            if pruned.contains(name) && !archive_path.exists() {
                pruned_seen += 1;
                entries += 1;
                continue;
            }
            let bytes = std::fs::read(&archive_path).map_err(|e| {
                format!(
                    "line {}: cannot read {}: {e}",
                    line_no + 1,
                    archive_path.display()
                )
            })?;
            let digest = format!("0x{}", hex::encode(tessera_broker::merkle::keccak(&bytes)));
            let expected = value
                .get("digest")
                .and_then(|d| d.as_str())
                .unwrap_or_default();
            if !digest.eq_ignore_ascii_case(expected) {
                return Err(format!(
                    "line {}: {} does not match the indexed digest (archive was rewritten)",
                    line_no + 1,
                    archive_path.display()
                ));
            }
            total_bytes += bytes.len() as u64;
        }
        entries += 1;
    }
    if entries == 0 {
        return Err("archive index is empty".into());
    }
    println!(
        "OK  archive index entries={entries}{}{} path={}",
        if args.check_files {
            format!(" verifiedBytes={total_bytes}")
        } else {
            String::new()
        },
        if pruned_seen > 0 {
            format!(" pruned={pruned_seen}")
        } else {
            String::new()
        },
        file.display()
    );
    Ok(())
}

/// Verify a restore attestation (`tessera-restore --attest` output).
fn verify_attestation(path: &str, args: &Args) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut document: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid attestation: {e}"))?;
    let snapshot: SignedPayload = serde_json::from_value(
        document
            .as_object_mut()
            .ok_or("attestation must be a JSON object")?
            .remove("snapshot")
            .ok_or("attestation has no snapshot")?,
    )
    .map_err(|e| format!("invalid snapshot: {e}"))?;
    let certificate = document
        .get("certificate")
        .cloned()
        .ok_or("attestation has no certificate")?;

    if !signer_ok(&snapshot.signer, &args.expect_signers) {
        return Err(format!(
            "attestation signer is {} but a different key was expected",
            snapshot.signer
        ));
    }
    if !tessera_broker::export::verify_signed_payload(
        tessera_broker::export::RESTORE_DOMAIN,
        &certificate,
        &snapshot,
        &args.expect_signers,
    )
    .map_err(|e| e.to_string())?
    {
        return Err("attestation digest or signature check failed".into());
    }
    println!(
        "OK  restore attestation tenant={} agents={} receipts={} operator={} restoredAt={}",
        certificate
            .get("tenant")
            .and_then(|t| t.as_str())
            .unwrap_or("(unknown)"),
        certificate
            .get("agentCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        certificate
            .get("receiptCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        snapshot.signer,
        certificate
            .get("restoredAt")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)"),
    );
    Ok(())
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

    let result = if let Some(path) = &args.limits {
        verify_limits_snapshot(path, &args)
    } else if let Some(dir) = &args.archive {
        verify_archive_dir(dir, &args)
    } else if let Some(index) = &args.archive_index {
        verify_archive_index(index, &args)
    } else if let Some(attestation) = &args.attestation {
        verify_attestation(attestation, &args)
    } else {
        verify_bundle_file(args.path.as_deref().unwrap_or_default(), &args)
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("INVALID: {message}");
            ExitCode::FAILURE
        }
    }
}
