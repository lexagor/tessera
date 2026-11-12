//! Background anchor scheduler.
//!
//! Periodically sweeps every tenant/agent chain and anchors any whose root has changed
//! since the last recorded anchor. No-ops when on-chain anchoring is not configured.

use std::sync::Arc;
use std::time::Duration;

use crate::error::BrokerError;
use crate::http::AppState;

/// Spawn the sweep loop. Skips the immediate first tick.
const LEADER_KEY: &str = "tessera:broker:scheduler:leader";

async fn renew_leader(state: &AppState, token: &str, ttl_secs: u64) -> Result<bool, BrokerError> {
    match state.cache.get(LEADER_KEY).await? {
        Some(current) if current == token => {
            state.cache.put(LEADER_KEY, token, ttl_secs).await?;
            Ok(true)
        }
        Some(_) => Ok(false),
        None => state.cache.put_if_absent(LEADER_KEY, token, ttl_secs).await,
    }
}

pub fn spawn(state: Arc<AppState>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        let leader_token = uuid::Uuid::new_v4().to_string();
        let leader_ttl = interval.as_secs().saturating_mul(2).saturating_add(30);
        let mut last_retention = tokio::time::Instant::now();
        let archive_interval = Duration::from_secs(state.service.archive_interval_secs.max(60));
        // `None` = never archived yet: the first sweep archives (evidence exists at startup).
        let mut last_archive: Option<tokio::time::Instant> = None;
        loop {
            ticker.tick().await;
            match renew_leader(&state, &leader_token, leader_ttl).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!("scheduler leader lock failed: {error}");
                    continue;
                }
            }
            match sweep(&state).await {
                Ok(n) if n > 0 => tracing::info!(anchored = n, "anchor sweep complete"),
                Ok(_) => {}
                Err(e) => tracing::warn!("anchor sweep failed: {e}"),
            }
            // Anchor gap detection: warn when chains run ahead of their anchors.
            if state.service.anchor.is_some() || state.service.anchor_gap_threshold > 0 {
                if let Err(e) = report_anchor_gaps(&state).await {
                    tracing::warn!("anchor gap check failed: {e}");
                }
            }
            // API keys expiring soon (alert + count).
            if let Err(e) = report_expiring_keys(&state).await {
                tracing::warn!("key expiry check failed: {e}");
            }
            // API keys past their rotation age.
            if let Err(e) = report_rotation_due(&state).await {
                tracing::warn!("key rotation check failed: {e}");
            }
            // Evidence retention: prune old archives/snapshots (index + newest snapshot kept).
            if let Some(dir) = state.service.archive_dir.clone() {
                if state.service.archive_retention_days > 0 {
                    if let Err(e) = state
                        .service
                        .prune_evidence(
                            std::path::Path::new(&dir),
                            state.service.archive_retention_days,
                        )
                        .await
                    {
                        tracing::warn!("evidence pruning failed: {e}");
                    }
                }
            }
            // Chains that no longer match their archived checkpoints.
            if let Err(e) = report_chain_drift(&state).await {
                tracing::warn!("chain drift check failed: {e}");
            }
            // Scheduled tenant archives (independent evidence retention).
            let archive_due = last_archive
                .map(|last| last.elapsed() >= archive_interval)
                .unwrap_or(true);
            if state.service.archive_dir.is_some() && archive_due {
                match archive_tenants(&state).await {
                    // Only start the interval once something was archived: a broker that
                    // started empty must not wait a full interval for its first evidence.
                    Ok(written) if written > 0 => {
                        last_archive = Some(tokio::time::Instant::now());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("scheduled archiving failed: {e}");
                        last_archive = Some(tokio::time::Instant::now());
                    }
                }
            }
            // Ledger compaction shares the retention cadence.
            if state.service.ledger_retention_days > 0
                && last_retention.elapsed() >= Duration::from_secs(3600)
            {
                match state
                    .service
                    .compact_ledgers(state.service.ledger_retention_days)
                    .await
                {
                    Ok(removed) if removed > 0 => {
                        tracing::info!(removed, "key-event ledgers compacted")
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("ledger compaction failed: {e}"),
                }
            }
            // Retention runs at most hourly (idempotent across replicas).
            if state.service.retention_days > 0
                && last_retention.elapsed() >= Duration::from_secs(3600)
            {
                if let Err(e) = state
                    .service
                    .run_retention(state.service.retention_days)
                    .await
                {
                    tracing::warn!("retention sweep failed: {e}");
                }
                last_retention = tokio::time::Instant::now();
            }
        }
    });
}

/// Count (and log) agents whose chains have grown past the configured anchor gap.
pub async fn report_anchor_gaps(state: &AppState) -> Result<usize, BrokerError> {
    let threshold = state.service.anchor_gap_threshold;
    if threshold == 0 {
        return Ok(0);
    }
    let mut flagged = 0;
    for tenant in state.service.chain.tenants().await? {
        let gaps = state.service.anchor_gaps(&tenant).await?;
        for gap in &gaps {
            let size = gap["gap"].as_u64().unwrap_or(0);
            if size >= threshold {
                flagged += 1;
                crate::metrics::anchor_gap_event();
                tracing::warn!(
                    tenant = %tenant,
                    agent = %gap["agent"].as_str().unwrap_or(""),
                    gap = size,
                    threshold,
                    "chain has grown past its last anchor"
                );
                let chain_length = gap["chainLength"].as_u64().unwrap_or(0);
                let agent = gap["agent"].as_str().unwrap_or("").to_string();
                if let Err(e) = state
                    .service
                    .alert_anchor_gap(&tenant, &agent, size, chain_length)
                    .await
                {
                    tracing::warn!(tenant = %tenant, "alert webhook failed: {e}");
                }
            }
        }
        // Conditions that cleared lose their acknowledgements, so a recurrence alerts.
        let active: Vec<String> = gaps
            .iter()
            .filter_map(|gap| gap["agent"].as_str().map(str::to_string))
            .collect();
        if let Err(e) = state
            .service
            .alert_acks
            .retain(&tenant, "anchor.gap", &active)
            .await
        {
            tracing::warn!(tenant = %tenant, "alert ack pruning failed: {e}");
        }
        // Heal immediately (bounded): don't wait for the next sweep's ordering.
        match state.service.heal_anchor_gaps(&tenant, 10).await {
            Ok(healed) if !healed.is_empty() => {
                tracing::info!(tenant = %tenant, healed = healed.len(), "gap-triggered anchors")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(tenant = %tenant, "gap healing failed: {e}"),
        }
    }
    Ok(flagged)
}

/// Alert on API keys expiring within the configured window (and count them).
pub async fn report_expiring_keys(state: &AppState) -> Result<usize, BrokerError> {
    let days = state.service.key_expiry_alert_days;
    if days == 0 {
        return Ok(0);
    }
    let now = chrono::Utc::now();
    let cutoff = now + chrono::Duration::days(days as i64);
    let mut expiring = 0usize;
    for tenant in state.service.chain.tenants().await? {
        let mut live_keys: Vec<String> = Vec::new();
        for record in state.keys.list(&tenant).await? {
            let Some(raw) = record.expires_at.as_deref() else {
                continue;
            };
            let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(raw) else {
                continue;
            };
            let expires_at = expires_at.with_timezone(&chrono::Utc);
            if expires_at > cutoff || !crate::auth::record_is_live(&record, now) {
                continue;
            }
            expiring += 1;
            live_keys.push(record.id.clone());
            crate::metrics::key_expiry_event();
            tracing::warn!(
                tenant = %tenant,
                key = %record.prefix,
                name = %record.name,
                expires_at = %expires_at.to_rfc3339(),
                "API key expiring soon"
            );
            if let Err(e) = state
                .service
                .send_alert(
                    &tenant,
                    "key.expiring",
                    &record.id,
                    (expires_at - now).num_seconds().max(0) as u64,
                    serde_json::json!({
                        "tenant": tenant,
                        "keyId": record.id,
                        "name": record.name,
                        "prefix": record.prefix,
                        "expiresAt": record.expires_at,
                        "secondsRemaining": (expires_at - now).num_seconds().max(0),
                    }),
                )
                .await
            {
                tracing::warn!(tenant = %tenant, "key expiry alert failed: {e}");
            }
        }
        if let Err(e) = state
            .service
            .alert_acks
            .retain(&tenant, "key.expiring", &live_keys)
            .await
        {
            tracing::warn!(tenant = %tenant, "key expiry ack pruning failed: {e}");
        }
    }
    Ok(expiring)
}

/// Alert when a live chain no longer matches its archived checkpoint.
pub async fn report_chain_drift(state: &AppState) -> Result<usize, BrokerError> {
    let mut drifted = 0usize;
    let mut affected: Vec<String> = Vec::new();
    for tenant in state.service.chain.tenants().await? {
        let drifts = state.service.chain_drift(&tenant).await?;
        if !drifts.is_empty() {
            affected.push(tenant.clone());
        }
        for drift in drifts {
            drifted += 1;
            crate::metrics::chain_drift_event();
            tracing::error!(
                tenant = %tenant,
                agent = %drift.agent,
                kind = %drift.kind,
                checkpoint_count = drift.checkpoint_count,
                live_count = drift.live_count,
                "chain drifted from its archived checkpoint"
            );
            if let Err(e) = state
                .service
                .send_alert(
                    &tenant,
                    "chain.drift",
                    &drift.agent,
                    drift.severity,
                    serde_json::json!({
                        "tenant": tenant,
                        "agent": drift.agent,
                        "kind": drift.kind,
                        "checkpointCount": drift.checkpoint_count,
                        "liveCount": drift.live_count,
                    }),
                )
                .await
            {
                tracing::warn!(tenant = %tenant, "drift alert failed: {e}");
            }
        }
    }

    // Re-archive affected tenants so a fresh checkpoint records reality; the older archive
    // (with the pre-drift checkpoint) remains on disk and indexed as evidence.
    if state.service.archive_dir.is_some() {
        let dir = state
            .service
            .archive_dir
            .clone()
            .expect("archive_dir checked above");
        for tenant in affected {
            match state
                .service
                .write_tenant_archive(&tenant, std::path::Path::new(&dir))
                .await
            {
                Ok(Some(path)) => {
                    crate::metrics::drift_rearchive();
                    tracing::warn!(
                        tenant = %tenant,
                        path = %path.display(),
                        "re-archived tenant after drift; the previous archive remains as evidence"
                    );
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(tenant = %tenant, "drift re-archive failed: {e}"),
            }
        }
    }
    Ok(drifted)
}

/// Report API keys that are past their rotation age.
pub async fn report_rotation_due(state: &AppState) -> Result<usize, BrokerError> {
    let Some(max_age_hours) = state.service.key_rotation_max_age_hours else {
        return Ok(0);
    };
    let now = chrono::Utc::now();
    let mut due = 0usize;
    for tenant in state.service.chain.tenants().await? {
        for record in state.keys.list(&tenant).await? {
            let Some(overdue_hours) = crate::auth::rotation_due_hours(&record, now, max_age_hours)
            else {
                continue;
            };
            due += 1;
            crate::metrics::key_rotation_due();
            tracing::warn!(
                tenant = %tenant,
                key = %record.prefix,
                name = %record.name,
                overdue_hours,
                max_age_hours,
                "API key is due for rotation"
            );
            if let Err(e) = state
                .service
                .send_alert(
                    &tenant,
                    "key.rotation-due",
                    &record.id,
                    overdue_hours,
                    serde_json::json!({
                        "tenant": tenant,
                        "keyId": record.id,
                        "name": record.name,
                        "prefix": record.prefix,
                        "lastRotatedAt": record.rotated_at,
                        "createdAt": record.created_at,
                        "overdueHours": overdue_hours,
                        "maxAgeHours": max_age_hours,
                    }),
                )
                .await
            {
                tracing::warn!(tenant = %tenant, "rotation alert failed: {e}");
            }
        }
    }
    Ok(due)
}

/// Write a signed archive per tenant into `ARCHIVE_DIR`.
pub async fn archive_tenants(state: &AppState) -> Result<usize, BrokerError> {
    let Some(dir) = state.service.archive_dir.as_deref() else {
        return Ok(0);
    };
    let dir = std::path::Path::new(dir);
    let mut written = 0;
    for tenant in state.service.chain.tenants().await? {
        match state.service.write_tenant_archive(&tenant, dir).await {
            Ok(Some(path)) => {
                written += 1;
                tracing::info!(tenant = %tenant, path = %path.display(), "tenant archive written");
            }
            Ok(None) => {}
            Err(e) => {
                crate::metrics::archive_failure();
                tracing::warn!(tenant = %tenant, "archive failed: {e}");
            }
        }
        // Signed posture snapshot beside the evidence, with a signed diff against the
        // previous snapshot so posture changes are part of the record.
        match integrity_snapshot_payload(state, &tenant).await {
            Ok(Some(mut payload)) => {
                if let Some(previous) =
                    crate::authorize::AuthorizeService::previous_snapshot(dir, &tenant)
                {
                    let changes =
                        crate::authorize::AuthorizeService::diff_snapshots(&previous, &payload);
                    let unexpected: Vec<&serde_json::Value> = changes
                        .iter()
                        .filter(|change| change["unexpected"] == true)
                        .collect();
                    if !unexpected.is_empty() {
                        let severity = unexpected.len() as u64;
                        tracing::warn!(
                            tenant = %tenant,
                            unexpected = severity,
                            "integrity posture changed unexpectedly"
                        );
                        if let Err(e) = state
                            .service
                            .send_alert(
                                &tenant,
                                "integrity.changed",
                                "posture",
                                severity,
                                serde_json::json!({
                                    "tenant": tenant,
                                    "changes": unexpected,
                                }),
                            )
                            .await
                        {
                            tracing::warn!(tenant = %tenant, "integrity change alert failed: {e}");
                        }
                    }
                    if let Some(object) = payload.as_object_mut() {
                        object.insert("changes".into(), serde_json::json!(changes));
                    }
                }
                match state
                    .service
                    .write_signed_snapshot(dir, "integrity", &tenant, payload)
                    .await
                {
                    Ok((path, _)) => {
                        tracing::info!(tenant = %tenant, path = %path.display(), "integrity snapshot written")
                    }
                    Err(e) => tracing::warn!(tenant = %tenant, "integrity snapshot failed: {e}"),
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(tenant = %tenant, "integrity report failed: {e}"),
        }
    }
    Ok(written)
}

/// Build the integrity payload for a tenant (None when the tenant has no chains).
pub async fn integrity_snapshot_payload(
    state: &AppState,
    tenant: &str,
) -> Result<Option<serde_json::Value>, BrokerError> {
    if state
        .service
        .chain
        .agents_for_tenant(tenant)
        .await?
        .is_empty()
    {
        return Ok(None);
    }
    let mut report = state.service.integrity_report(tenant).await?;
    let now = chrono::Utc::now();
    let records = state.keys.list(tenant).await?;
    let posture = crate::auth::key_posture(
        &records,
        now,
        state.service.key_expiry_alert_days,
        state.service.key_rotation_max_age_hours,
    );
    // Settings are captured (redacted) so the signed snapshot is evidence of configuration,
    // not just of data. `settings.digest` changing between snapshots appears in the diff.
    let anchor = state
        .service
        .anchor_targets
        .get(tenant)
        .await?
        .map(|target| {
            serde_json::json!({
                "chainId": target.chain_id,
                "rpcHost": crate::http::url_host(&target.rpc_url),
                "contract": target.contract,
                "hasPrivateKey": target.private_key.is_some(),
                "signerHistory": target.signer_history,
            })
        })
        .unwrap_or(serde_json::Value::Null);
    let alert = state
        .service
        .alert_target(tenant)
        .await?
        .map(|target| {
            serde_json::json!({
                "host": crate::http::url_host(&target.url),
                "events": target.events,
                "hasToken": target.token.is_some(),
            })
        })
        .unwrap_or(serde_json::Value::Null);
    let remediation = state
        .service
        .remediation_policies
        .get(tenant)
        .await?
        .map(|policy| serde_json::json!(policy))
        .unwrap_or(serde_json::Value::Null);
    let settings = serde_json::json!({
        "anchor": anchor,
        "alert": alert,
        "remediation": remediation,
    });
    let settings_digest = crate::canonical::hash_json(&settings);
    if let Some(object) = report.as_object_mut() {
        object.insert("keys".into(), posture);
        object.insert(
            "settings".into(),
            serde_json::json!({ "digest": settings_digest, "anchor": anchor, "alert": alert, "remediation": remediation }),
        );
    }
    Ok(Some(report))
}

/// One sweep: returns the number of chains newly anchored.
pub async fn sweep(state: &AppState) -> Result<usize, BrokerError> {
    if state.service.anchor.is_none() {
        return Ok(0);
    }
    let tenants = state.service.chain.tenants().await?;
    let mut anchored = 0usize;
    for tenant in tenants {
        for agent in state.service.chain.agents_for_tenant(&tenant).await? {
            match state
                .service
                .anchor_and_record(&tenant, &agent, false)
                .await
            {
                Ok(Some(_)) => anchored += 1,
                Ok(None) => {}
                Err(e) => tracing::warn!(tenant = %tenant, agent = %agent, "anchor failed: {e}"),
            }
        }
        // Re-check any anchors still pending confirmation.
        match state.service.reconfirm_anchors(&tenant).await {
            Ok(n) if n > 0 => tracing::info!(tenant = %tenant, updated = n, "reconfirmed anchors"),
            Ok(_) => {}
            Err(e) => tracing::warn!(tenant = %tenant, "anchor reconfirm failed: {e}"),
        }
    }
    Ok(anchored)
}
