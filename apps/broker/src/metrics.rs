//! Lightweight in-process metrics exposed in Prometheus text format at `/metrics`.
//!
//! Deliberately dependency-free: atomic counters and a text renderer. Enough for
//! dashboards/alerts without pulling in a metrics framework.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

#[derive(Default)]
pub struct Metrics {
    pub authorize_allow: AtomicU64,
    pub authorize_deny: AtomicU64,
    pub credentials_issued: AtomicU64,
    pub proxy_calls: AtomicU64,
    pub proxy_denied: AtomicU64,
    pub anchor_submissions: AtomicU64,
    pub anchor_failures: AtomicU64,
    pub revocations: AtomicU64,
    pub verify_calls: AtomicU64,
    pub export_bundles: AtomicU64,
    pub throttled: AtomicU64,
    pub archives_written: AtomicU64,
    pub archive_failures: AtomicU64,
    pub anchor_gap_events: AtomicU64,
    pub anchor_gap_heal_attempts: AtomicU64,
    pub anchor_gap_healed: AtomicU64,
    pub archive_replicas: AtomicU64,
    pub archive_replica_failures: AtomicU64,
    pub alerts_sent: AtomicU64,
    pub alert_failures: AtomicU64,
    pub key_expiry_events: AtomicU64,
    pub imported_receipts: AtomicU64,
    pub alerts_auto_acked: AtomicU64,
    pub key_rotation_due: AtomicU64,
    pub key_events: AtomicU64,
    pub chain_drift_events: AtomicU64,
    pub quota_rejections: AtomicU64,
    pub integrity_snapshots: AtomicU64,
    pub drift_rearchives: AtomicU64,
    pub restore_attestations: AtomicU64,
    pub evidence_pruned: AtomicU64,
    pub auto_remediations: AtomicU64,
    pub remediation_stale: AtomicU64,
    pub ledger_compacted: AtomicU64,
    pub tool_drift_denials: AtomicU64,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(Metrics::default)
}

macro_rules! inc {
    ($field:ident) => {
        metrics().$field.fetch_add(1, Ordering::Relaxed);
    };
}

pub fn authorize_allow() {
    inc!(authorize_allow);
}
pub fn authorize_deny() {
    inc!(authorize_deny);
}
pub fn credential_issued() {
    inc!(credentials_issued);
}
pub fn proxy_call() {
    inc!(proxy_calls);
}
pub fn proxy_denied() {
    inc!(proxy_denied);
}
pub fn anchor_submission() {
    inc!(anchor_submissions);
}
pub fn anchor_failure() {
    inc!(anchor_failures);
}
pub fn revocation() {
    inc!(revocations);
}
pub fn verify_call() {
    inc!(verify_calls);
}
pub fn export_bundle() {
    inc!(export_bundles);
}
pub fn throttled() {
    inc!(throttled);
}
pub fn archive_written() {
    inc!(archives_written);
}
pub fn archive_failure() {
    inc!(archive_failures);
}
pub fn anchor_gap_event() {
    inc!(anchor_gap_events);
}
pub fn anchor_gap_heal_attempt() {
    inc!(anchor_gap_heal_attempts);
}
pub fn anchor_gap_healed() {
    inc!(anchor_gap_healed);
}
pub fn archive_replicated() {
    inc!(archive_replicas);
}
pub fn archive_replica_failure() {
    inc!(archive_replica_failures);
}
pub fn alert_sent() {
    inc!(alerts_sent);
}
pub fn alert_failure() {
    inc!(alert_failures);
}
pub fn key_expiry_event() {
    inc!(key_expiry_events);
}
pub fn imported_receipts(count: u64) {
    metrics()
        .imported_receipts
        .fetch_add(count, Ordering::Relaxed);
}
pub fn alert_auto_acked() {
    inc!(alerts_auto_acked);
}
pub fn key_rotation_due() {
    inc!(key_rotation_due);
}
pub fn key_event_recorded() {
    inc!(key_events);
}
pub fn chain_drift_event() {
    inc!(chain_drift_events);
}
pub fn quota_rejection() {
    inc!(quota_rejections);
}
pub fn integrity_snapshot() {
    inc!(integrity_snapshots);
}
pub fn drift_rearchive() {
    inc!(drift_rearchives);
}
pub fn restore_attestation() {
    inc!(restore_attestations);
}
pub fn evidence_pruned() {
    inc!(evidence_pruned);
}
pub fn auto_remediated() {
    inc!(auto_remediations);
}
pub fn remediation_stale() {
    inc!(remediation_stale);
}
pub fn ledger_compacted(removed: u64) {
    metrics()
        .ledger_compacted
        .fetch_add(removed, Ordering::Relaxed);
}
pub fn tool_drift_denial() {
    inc!(tool_drift_denials);
}

/// Render the counters in Prometheus text exposition format.
pub fn render() -> String {
    let m = metrics();
    let mut out = String::new();
    let pairs: [(&str, &AtomicU64, &str); 35] = [
        (
            "tessera_authorize_allow_total",
            &m.authorize_allow,
            "authorizations allowed",
        ),
        (
            "tessera_authorize_deny_total",
            &m.authorize_deny,
            "authorizations denied",
        ),
        (
            "tessera_credentials_issued_total",
            &m.credentials_issued,
            "ephemeral credentials issued",
        ),
        (
            "tessera_proxy_calls_total",
            &m.proxy_calls,
            "grant proxy calls",
        ),
        (
            "tessera_proxy_denied_total",
            &m.proxy_denied,
            "grant proxy calls denied",
        ),
        (
            "tessera_anchor_submissions_total",
            &m.anchor_submissions,
            "on-chain anchor submissions",
        ),
        (
            "tessera_anchor_failures_total",
            &m.anchor_failures,
            "on-chain anchor failures",
        ),
        (
            "tessera_revocations_total",
            &m.revocations,
            "revocations recorded",
        ),
        (
            "tessera_export_bundles_total",
            &m.export_bundles,
            "signed audit exports",
        ),
        (
            "tessera_throttled_total",
            &m.throttled,
            "requests rejected by rate limits",
        ),
        (
            "tessera_archives_written_total",
            &m.archives_written,
            "scheduled tenant archives written",
        ),
        (
            "tessera_archive_failures_total",
            &m.archive_failures,
            "scheduled tenant archive failures",
        ),
        (
            "tessera_anchor_gap_events_total",
            &m.anchor_gap_events,
            "chains found past the anchor gap threshold",
        ),
        (
            "tessera_anchor_gap_heal_attempts_total",
            &m.anchor_gap_heal_attempts,
            "forced anchors attempted for gapped chains",
        ),
        (
            "tessera_anchor_gap_healed_total",
            &m.anchor_gap_healed,
            "forced anchors submitted for gapped chains",
        ),
        (
            "tessera_archive_replicas_total",
            &m.archive_replicas,
            "archives replicated to the second location",
        ),
        (
            "tessera_archive_replica_failures_total",
            &m.archive_replica_failures,
            "archive replication failures",
        ),
        (
            "tessera_alerts_sent_total",
            &m.alerts_sent,
            "anchor-gap alert webhooks delivered",
        ),
        (
            "tessera_alert_failures_total",
            &m.alert_failures,
            "alert webhook failures",
        ),
        (
            "tessera_key_expiry_events_total",
            &m.key_expiry_events,
            "API keys found expiring soon",
        ),
        (
            "tessera_imported_receipts_total",
            &m.imported_receipts,
            "receipts imported from evidence archives",
        ),
        (
            "tessera_alerts_auto_acked_total",
            &m.alerts_auto_acked,
            "alerts suppressed by auto-ack policy",
        ),
        (
            "tessera_key_rotation_due_total",
            &m.key_rotation_due,
            "API keys past their rotation age",
        ),
        (
            "tessera_key_events_total",
            &m.key_events,
            "key lifecycle events recorded in the ledger",
        ),
        (
            "tessera_chain_drift_events_total",
            &m.chain_drift_events,
            "live chains that drifted from their checkpoints",
        ),
        (
            "tessera_quota_rejections_total",
            &m.quota_rejections,
            "provider calls rejected by quota reservations",
        ),
        (
            "tessera_integrity_snapshots_total",
            &m.integrity_snapshots,
            "signed integrity snapshots written",
        ),
        (
            "tessera_drift_rearchives_total",
            &m.drift_rearchives,
            "tenants re-archived after drift detection",
        ),
        (
            "tessera_restore_attestations_total",
            &m.restore_attestations,
            "restore attestations issued",
        ),
        (
            "tessera_evidence_pruned_total",
            &m.evidence_pruned,
            "evidence files pruned by retention policy",
        ),
        (
            "tessera_auto_remediations_total",
            &m.auto_remediations,
            "keys narrowed by auto-remediation policy",
        ),
        (
            "tessera_remediation_stale_total",
            &m.remediation_stale,
            "auto-remediation decisions skipped because the template changed",
        ),
        (
            "tessera_ledger_compacted_total",
            &m.ledger_compacted,
            "ledger events pruned by compaction",
        ),
        (
            "tessera_tool_drift_denials_total",
            &m.tool_drift_denials,
            "calls refused because a pinned tool definition changed",
        ),
        (
            "tessera_verify_calls_total",
            &m.verify_calls,
            "verification requests",
        ),
    ];
    for (name, counter, help) in pairs {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} counter\n"));
        out.push_str(&format!("{name} {}\n", counter.load(Ordering::Relaxed)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        authorize_allow();
        let text = render();
        assert!(text.contains("# TYPE tessera_authorize_allow_total counter"));
        assert!(text.contains("tessera_authorize_allow_total "));
    }
}
