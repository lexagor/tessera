//! Telemetry graph + least-privilege policy proposal.
//!
//! Every allowed call records the *shape* of its arguments (numeric ranges and small string
//! value sets) — never raw payloads. `propose` turns those observations into a draft policy:
//! numeric fields become min/max constraints, low-cardinality string fields become
//! allowlists, and consistently-present fields become required.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::BrokerError;
use crate::policy::{Constraint, Policy, PolicyMode, ResourceGrant};

/// Distinct string values beyond this are left unconstrained (avoids brittle allowlists).
pub const ALLOWLIST_MAX_VALUES: usize = 8;
/// Strings longer than this are not tracked as allowlist candidates.
pub const ALLOWLIST_MAX_LEN: usize = 64;
/// Distinct string values tracked per (resource, field); beyond this new values are dropped
/// (bounds storage growth from attacker-chosen values).
pub const MAX_TEXT_VALUES: usize = 64;
/// Placeholder stored instead of values that look like PII or credentials.
pub const REDACTED: &str = "<redacted>";

/// Whether a string looks like a secret or personal datum that must not be persisted in the
/// telemetry graph. Conservative: helps with the common cases (emails, card/account numbers,
/// provider tokens, JWTs, PEM blocks) rather than claiming full DLP.
pub fn looks_sensitive(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    const PREFIXES: [&str; 14] = [
        "sk_",
        "pk_",
        "rk_",
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "akia",
        "asia",
        "eyj",
        "bearer ",
        "-----begin",
    ];
    if PREFIXES.iter().any(|prefix| lower.starts_with(prefix)) {
        return true;
    }
    // Email addresses.
    if let Some((local, domain)) = value.split_once('@') {
        if !local.is_empty() && domain.contains('.') && !domain.contains('/') {
            return true;
        }
    }
    // Long digit runs (card / account / phone numbers), allowing separators.
    let digits = value.chars().filter(char::is_ascii_digit).count();
    digits >= 13
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || " -".contains(c))
}

/// Value recorded for a string field: redacted when it looks sensitive.
fn recorded_text(value: &str) -> String {
    if looks_sensitive(value) {
        REDACTED.to_string()
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone)]
pub enum ObservedField {
    Number { field: String, value: f64 },
    Text { field: String, value: String },
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub tenant: String,
    pub resource: String,
    pub fields: Vec<ObservedField>,
}

/// Aggregate observation for a (resource, field).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldStat {
    pub resource: String,
    pub field: String,
    /// `"number"` or `"string"`.
    pub kind: String,
    pub count: u64,
    pub total_calls: u64,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub values: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedPolicy {
    pub policy: Policy,
    pub evidence: Vec<FieldStat>,
    pub notes: Vec<String>,
}

#[async_trait]
pub trait TelemetryStore: Send + Sync {
    async fn record(&self, obs: &Observation) -> Result<(), BrokerError>;
    async fn stats(&self, tenant: &str) -> Result<Vec<FieldStat>, BrokerError>;
    /// Drop resources with no observed activity since `cutoff`. Returns resources removed.
    async fn prune_idle_before(
        &self,
        _cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        Ok(0)
    }
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

/// Flatten a JSON argument object into observed fields (dotted paths for nested objects).
pub fn observe_fields(args: &Value, fields: &mut Vec<ObservedField>) {
    if let Value::Object(map) = args {
        collect(map, "", fields);
    }
}

fn collect(map: &serde_json::Map<String, Value>, prefix: &str, out: &mut Vec<ObservedField>) {
    for (key, value) in map {
        let field = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            Value::Object(inner) => collect(inner, &field, out),
            Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    out.push(ObservedField::Number { field, value: f });
                }
            }
            Value::String(s) if s.chars().count() <= ALLOWLIST_MAX_LEN => {
                out.push(ObservedField::Text {
                    field,
                    value: recorded_text(s),
                });
            }
            Value::Bool(b) => out.push(ObservedField::Text {
                field,
                value: b.to_string(),
            }),
            _ => {}
        }
    }
}

/// Turn observed field statistics into a draft least-privilege policy.
pub fn propose(stats: &[FieldStat]) -> ProposedPolicy {
    let mut notes = Vec::new();
    let mut by_resource: BTreeMap<&str, Vec<&FieldStat>> = BTreeMap::new();
    for stat in stats {
        by_resource
            .entry(stat.resource.as_str())
            .or_default()
            .push(stat);
    }

    let mut grants = Vec::new();
    for (resource, mut fields) in by_resource {
        fields.sort_by(|a, b| a.field.cmp(&b.field));
        let mut constraints = Vec::new();
        for stat in fields {
            if stat.total_calls >= 2 && stat.count == stat.total_calls {
                constraints.push(Constraint::Required {
                    field: stat.field.clone(),
                });
            }
            match stat.kind.as_str() {
                "number" => {
                    if let Some(min) = stat.min {
                        constraints.push(Constraint::MinNumber {
                            field: stat.field.clone(),
                            value: min,
                        });
                    }
                    if let Some(max) = stat.max {
                        constraints.push(Constraint::MaxNumber {
                            field: stat.field.clone(),
                            value: max,
                        });
                    }
                }
                "string" => {
                    if stat.truncated || stat.values.len() > ALLOWLIST_MAX_VALUES {
                        notes.push(format!(
                            "{resource}: field '{}' has {} distinct values; left unconstrained",
                            stat.field,
                            stat.values.len()
                        ));
                    } else {
                        let values: Vec<String> = stat
                            .values
                            .iter()
                            .filter(|value| value.as_str() != REDACTED)
                            .cloned()
                            .collect();
                        if !values.is_empty() {
                            constraints.push(Constraint::Allowlist {
                                field: stat.field.clone(),
                                values,
                            });
                        } else if !stat.values.is_empty() {
                            notes.push(format!(
                                "{resource}: field '{}' contained only redacted values; left unconstrained",
                                stat.field
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        grants.push(ResourceGrant {
            resource: resource.to_string(),
            constraints,
            condition: None,
        });
    }

    if grants.is_empty() {
        notes.push("no observed calls; cannot propose a policy".to_string());
    }

    ProposedPolicy {
        policy: Policy {
            id: "proposed".to_string(),
            version: 1,
            name: "Proposed least-privilege policy".to_string(),
            grants,
            fail_open: false,
            mode: PolicyMode::Enforce,
            limits: Default::default(),
        },
        evidence: stats.to_vec(),
        notes,
    }
}

// ── In-memory store ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct NumStat {
    count: u64,
    min: f64,
    max: f64,
}

#[derive(Default)]
struct ResourceStats {
    calls: u64,
    last_seen_ms: u64,
    numbers: HashMap<String, NumStat>,
    texts: HashMap<String, HashMap<String, u64>>,
}

#[derive(Default)]
pub struct MemoryTelemetryStore {
    data: Mutex<HashMap<(String, String), ResourceStats>>,
}

impl MemoryTelemetryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TelemetryStore for MemoryTelemetryStore {
    async fn record(&self, obs: &Observation) -> Result<(), BrokerError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| BrokerError::Internal("telemetry store poisoned".into()))?;
        let stats = data
            .entry((obs.tenant.clone(), obs.resource.clone()))
            .or_default();
        stats.calls += 1;
        stats.last_seen_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        for field in &obs.fields {
            match field {
                ObservedField::Number { field, value } => {
                    stats
                        .numbers
                        .entry(field.clone())
                        .and_modify(|s| {
                            s.count += 1;
                            s.min = s.min.min(*value);
                            s.max = s.max.max(*value);
                        })
                        .or_insert(NumStat {
                            count: 1,
                            min: *value,
                            max: *value,
                        });
                }
                ObservedField::Text { field, value } => {
                    let values = stats.texts.entry(field.clone()).or_default();
                    if let Some(count) = values.get_mut(value) {
                        *count += 1;
                    } else if values.len() < MAX_TEXT_VALUES {
                        // Cap distinct values per field; further novel values are dropped.
                        values.insert(value.clone(), 1);
                    }
                }
            }
        }
        Ok(())
    }

    async fn prune_idle_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BrokerError> {
        let cutoff_ms = cutoff.timestamp_millis().max(0) as u64;
        let mut data = self
            .data
            .lock()
            .map_err(|_| BrokerError::Internal("telemetry store poisoned".into()))?;
        let before = data.len();
        data.retain(|_, stats| stats.last_seen_ms >= cutoff_ms);
        Ok((before - data.len()) as u64)
    }

    async fn stats(&self, tenant: &str) -> Result<Vec<FieldStat>, BrokerError> {
        let data = self
            .data
            .lock()
            .map_err(|_| BrokerError::Internal("telemetry store poisoned".into()))?;
        let mut out = Vec::new();
        for ((t, resource), stats) in data.iter() {
            if t != tenant {
                continue;
            }
            for (field, s) in &stats.numbers {
                out.push(FieldStat {
                    resource: resource.clone(),
                    field: field.clone(),
                    kind: "number".into(),
                    count: s.count,
                    total_calls: stats.calls,
                    min: Some(s.min),
                    max: Some(s.max),
                    values: vec![],
                    truncated: false,
                });
            }
            for (field, values) in &stats.texts {
                let mut list: Vec<String> = values.keys().cloned().collect();
                list.sort();
                let truncated = list.len() > ALLOWLIST_MAX_VALUES;
                out.push(FieldStat {
                    resource: resource.clone(),
                    field: field.clone(),
                    kind: "string".into(),
                    count: values.values().sum(),
                    total_calls: stats.calls,
                    min: None,
                    max: None,
                    values: list,
                    truncated,
                });
            }
        }
        out.sort_by(|a, b| (&a.resource, &a.field, &a.kind).cmp(&(&b.resource, &b.field, &b.kind)));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn observe_flattens_nested_objects() {
        let mut fields = Vec::new();
        observe_fields(
            &json!({"amount": 10, "user": {"role": "admin"}, "tags": [1, 2]}),
            &mut fields,
        );
        assert_eq!(fields.len(), 2);
        assert!(
            matches!(&fields[0], ObservedField::Number { field, value } if field == "amount" && *value == 10.0)
        );
        assert!(
            matches!(&fields[1], ObservedField::Text { field, value } if field == "user.role" && value == "admin")
        );
    }

    #[tokio::test]
    async fn records_and_proposes_constraints() {
        let store = MemoryTelemetryStore::new();
        for (amount, currency) in [(100.0, "usd"), (700.0, "usd"), (250.0, "eur")] {
            let mut fields = Vec::new();
            observe_fields(
                &json!({"amount": amount, "currency": currency}),
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
        let constraints = &proposal.policy.grants[0].constraints;
        assert!(constraints.iter().any(|c| matches!(c, Constraint::MaxNumber { field, value } if field == "amount" && *value == 700.0)));
        assert!(constraints.iter().any(|c| matches!(c, Constraint::MinNumber { field, value } if field == "amount" && *value == 100.0)));
        assert!(constraints
            .iter()
            .any(|c| matches!(c, Constraint::Allowlist { field, .. } if field == "currency")));
        assert!(constraints
            .iter()
            .any(|c| matches!(c, Constraint::Required { field } if field == "amount")));
    }

    #[test]
    fn high_cardinality_strings_are_unconstrained() {
        let stats = vec![FieldStat {
            resource: "x".into(),
            field: "id".into(),
            kind: "string".into(),
            count: 10,
            total_calls: 10,
            min: None,
            max: None,
            values: (0..10).map(|i| format!("v{i}")).collect(),
            truncated: true,
        }];
        let proposal = propose(&stats);
        assert!(proposal.policy.grants[0]
            .constraints
            .iter()
            .all(|c| !matches!(c, Constraint::Allowlist { .. })));
        assert!(proposal.notes.iter().any(|n| n.contains("unconstrained")));
    }

    #[tokio::test]
    async fn string_cardinality_is_capped() {
        let store = MemoryTelemetryStore::new();
        for i in 0..(MAX_TEXT_VALUES + 20) {
            let mut fields = Vec::new();
            observe_fields(&json!({ "session": format!("s{i}") }), &mut fields);
            store
                .record(&Observation {
                    tenant: "acme".into(),
                    resource: "r".into(),
                    fields,
                })
                .await
                .unwrap();
        }
        let stats = store.stats("acme").await.unwrap();
        let session = stats.iter().find(|s| s.field == "session").unwrap();
        assert_eq!(
            session.values.len(),
            MAX_TEXT_VALUES,
            "distinct values are bounded"
        );
    }

    #[tokio::test]
    async fn prune_idle_before_removes_stale_resources() {
        let store = MemoryTelemetryStore::new();
        let mut fields = Vec::new();
        observe_fields(&json!({ "amount": 1 }), &mut fields);
        store
            .record(&Observation {
                tenant: "acme".into(),
                resource: "r".into(),
                fields,
            })
            .await
            .unwrap();

        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        assert_eq!(store.prune_idle_before(past).await.unwrap(), 0);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        assert_eq!(store.prune_idle_before(future).await.unwrap(), 1);
        assert!(store.stats("acme").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let store = MemoryTelemetryStore::new();
        store
            .record(&Observation {
                tenant: "a".into(),
                resource: "r".into(),
                fields: vec![ObservedField::Number {
                    field: "n".into(),
                    value: 1.0,
                }],
            })
            .await
            .unwrap();
        assert_eq!(store.stats("a").await.unwrap().len(), 1);
        assert!(store.stats("b").await.unwrap().is_empty());
    }

    #[test]
    fn sensitive_values_are_redacted_before_storage() {
        let args = serde_json::json!({
            "email": "alice@example.com",
            "card": "4242 4242 4242 4242",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "currency": "usd",
            "status": "refund"
        });
        let mut fields = Vec::new();
        observe_fields(&args, &mut fields);
        let by_field = |name: &str| {
            fields
                .iter()
                .find_map(|field| match field {
                    ObservedField::Text { field: f, value } if f == name => Some(value.clone()),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(by_field("email"), REDACTED);
        assert_eq!(by_field("card"), REDACTED);
        assert_eq!(by_field("jwt"), REDACTED);
        assert_eq!(by_field("aws"), REDACTED);
        // Ordinary enum-like values are preserved for policy proposals.
        assert_eq!(by_field("currency"), "usd");
        assert_eq!(by_field("status"), "refund");
    }

    #[test]
    fn proposals_do_not_allowlist_the_redaction_marker() {
        let stats = vec![FieldStat {
            resource: "stripe:refunds.create".into(),
            field: "email".into(),
            kind: "string".into(),
            count: 3,
            total_calls: 3,
            min: None,
            max: None,
            values: vec![REDACTED.to_string()],
            truncated: false,
        }];
        let proposal = propose(&stats);
        // Presence (`Required`) is fine; the redaction marker must never become an allowlist.
        assert!(!proposal.policy.grants[0].constraints.iter().any(
            |constraint| matches!(constraint, Constraint::Allowlist { values, .. }
                if values.iter().any(|value| value == REDACTED))
        ));
        assert!(proposal.notes.iter().any(|note| note.contains("redacted")));
    }
}
