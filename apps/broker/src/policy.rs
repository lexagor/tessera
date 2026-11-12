//! Policy model, store, and evaluation.
//!
//! A policy binds a resource to a set of grants. Each grant carries constraints over
//! the tool-call arguments. Evaluation is deny-by-default: a request is allowed only if
//! some grant matches the resource *and* all of its constraints pass.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use cel_interpreter::{Context as CelContext, Program, Value as CelValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical;
use crate::error::BrokerError;

/// A named resource granted to an agent, e.g. `stripe:refunds.create` or `aws:s3:GetObject`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGrant {
    pub resource: String,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    /// Optional CEL expression over the call context. Evaluated after constraints; must
    /// return a boolean. Variables: `resource`, `agent_id`, `user_id`, and one per
    /// top-level argument field (dotted access works for nested objects).
    #[serde(default)]
    pub condition: Option<String>,
}

/// Constraints evaluated against the tool-call arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Constraint {
    /// Argument must be a number <= `value`.
    MaxNumber { field: String, value: f64 },
    /// Argument must be a number >= `value`.
    MinNumber { field: String, value: f64 },
    /// Argument (string) must be one of `values`.
    Allowlist { field: String, values: Vec<String> },
    /// Argument (string) must start with `prefix`.
    Prefix { field: String, prefix: String },
    /// Field must be present and non-null.
    Required { field: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Set from the URL path on upsert; may be omitted in request bodies.
    #[serde(default)]
    pub id: String,
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub grants: Vec<ResourceGrant>,
    /// Allow the request if a grant matches but constraint evaluation errors. Default false.
    #[serde(default)]
    pub fail_open: bool,
    /// Operational limits for calls allowed by this policy. Always narrowed by the
    /// broker-wide ceilings (see `AuthorizeService::max_ttl_seconds`).
    #[serde(default)]
    pub limits: PolicyLimits,
}

/// Per-policy operational limits. Every field is optional; unset fields fall back to the
/// broker configuration. A policy can only *tighten* limits, never exceed the global caps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyLimits {
    /// Maximum credential lifetime (seconds) for calls this policy allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u32>,
    /// Per-agent budget (requests/minute) for calls this policy allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_rate_limit_per_min: Option<u32>,
    /// Per-resource budgets (`resource=per_minute`), merged over the broker configuration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_rate_limits: Vec<(String, u32)>,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub agent_id: String,
    pub user_id: String,
    pub resource: String,
    pub args: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    pub allow: bool,
    pub policy_id: String,
    pub policy_version: u32,
    /// Canonical hash of the policy content that produced this result (None when no policy
    /// matched). V2 receipts bind this hash so a policy edit cannot retroactively change the
    /// meaning of an old record.
    pub policy_hash: Option<String>,
    pub resource: String,
    pub anomaly_score: f64,
    pub reason: String,
    /// Limits carried by the policy that produced this result (empty when none/deny).
    #[serde(skip)]
    pub limits: PolicyLimits,
}

impl PolicyResult {
    pub fn deny(reason: impl Into<String>, resource: &str) -> Self {
        Self {
            allow: false,
            limits: PolicyLimits::default(),
            policy_id: String::new(),
            policy_version: 0,
            policy_hash: None,
            resource: resource.to_string(),
            anomaly_score: 0.0,
            reason: reason.into(),
        }
    }

    fn deny_for(policy: &Policy, reason: impl Into<String>, resource: &str) -> Self {
        Self {
            allow: false,
            limits: PolicyLimits::default(),
            policy_id: policy.id.clone(),
            policy_version: policy.version,
            policy_hash: Some(policy.content_hash()),
            resource: resource.to_string(),
            anomaly_score: 0.0,
            reason: reason.into(),
        }
    }
}

impl Policy {
    /// Canonical hash of the complete policy document. Deterministic across Rust and TS.
    pub fn content_hash(&self) -> String {
        match serde_json::to_value(self) {
            Ok(value) => canonical::hash_json(&value),
            Err(_) => canonical::keccak256_str("unserializable-policy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyVersion {
    pub id: String,
    pub version: u32,
    pub content_hash: String,
    pub document: serde_json::Value,
}

#[async_trait::async_trait]
pub trait PolicyStore: Send + Sync {
    /// Policies used for evaluation (active set) for a tenant.
    async fn policies_for(&self, tenant: &str) -> Result<Vec<Policy>, BrokerError>;
    async fn list(&self, tenant: &str) -> Result<Vec<Policy>, BrokerError>;
    async fn get(&self, tenant: &str, id: &str) -> Result<Option<Policy>, BrokerError>;
    /// Create or replace a policy (matched by `id`).
    async fn upsert(&self, tenant: &str, policy: Policy) -> Result<(), BrokerError>;
    /// Every retained policy version for a tenant (append-only history where available).
    async fn versions(&self, _tenant: &str) -> Result<Vec<PolicyVersion>, BrokerError> {
        Ok(Vec::new())
    }
    async fn delete(&self, tenant: &str, id: &str) -> Result<bool, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

/// In-memory policy store. Phase 1 stand-in for the control-plane database.
#[derive(Default)]
pub struct InMemoryPolicyStore {
    map: Mutex<HashMap<String, Vec<Policy>>>,
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<Policy>>>, BrokerError> {
        self.map
            .lock()
            .map_err(|_| BrokerError::Internal("policy store poisoned".into()))
    }
}

#[async_trait::async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn policies_for(&self, tenant: &str) -> Result<Vec<Policy>, BrokerError> {
        Ok(self.lock()?.get(tenant).cloned().unwrap_or_default())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<Policy>, BrokerError> {
        self.policies_for(tenant).await
    }

    async fn get(&self, tenant: &str, id: &str) -> Result<Option<Policy>, BrokerError> {
        Ok(self
            .lock()?
            .get(tenant)
            .and_then(|policies| policies.iter().find(|p| p.id == id))
            .cloned())
    }

    async fn upsert(&self, tenant: &str, policy: Policy) -> Result<(), BrokerError> {
        let new_hash = policy.content_hash();
        let mut map = self.lock()?;
        let policies = map.entry(tenant.to_string()).or_default();
        match policies.iter_mut().find(|p| p.id == policy.id) {
            Some(existing) => {
                if existing.version == policy.version && existing.content_hash() != new_hash {
                    return Err(BrokerError::Invalid(format!(
                        "policy '{}' version {} already exists with different content; increment the version",
                        policy.id, policy.version
                    )));
                }
                *existing = policy;
            }
            None => policies.push(policy),
        }
        Ok(())
    }

    async fn delete(&self, tenant: &str, id: &str) -> Result<bool, BrokerError> {
        let mut map = self.lock()?;
        let Some(policies) = map.get_mut(tenant) else {
            return Ok(false);
        };
        let before = policies.len();
        policies.retain(|p| p.id != id);
        Ok(policies.len() != before)
    }

    async fn versions(&self, tenant: &str) -> Result<Vec<PolicyVersion>, BrokerError> {
        let mut versions: Vec<PolicyVersion> = self
            .policies_for(tenant)
            .await?
            .into_iter()
            .map(|policy| PolicyVersion {
                id: policy.id.clone(),
                version: policy.version,
                content_hash: policy.content_hash(),
                document: serde_json::to_value(&policy).unwrap_or(Value::Null),
            })
            .collect();
        versions.sort_by(|a, b| (a.id.as_str(), a.version).cmp(&(b.id.as_str(), b.version)));
        Ok(versions)
    }
}

/// A permissive policy used for local demos when no policy is configured.
pub fn demo_policy() -> Policy {
    Policy {
        id: "demo".to_string(),
        version: 1,
        name: "Permissive demo policy".to_string(),
        grants: vec![ResourceGrant {
            resource: "*".to_string(),
            constraints: vec![],
            condition: None,
        }],
        fail_open: false,
        limits: PolicyLimits::default(),
    }
}

/// Evaluate `ctx` against a set of policies. First matching grant wins.
pub fn evaluate(policies: &[Policy], ctx: &PolicyContext) -> PolicyResult {
    for policy in policies {
        for grant in &policy.grants {
            if !resource_matches(&grant.resource, &ctx.resource) {
                continue;
            }
            match grant_allows(grant, ctx) {
                Ok(()) => {
                    return PolicyResult {
                        allow: true,
                        policy_id: policy.id.clone(),
                        policy_version: policy.version,
                        policy_hash: Some(policy.content_hash()),
                        resource: ctx.resource.clone(),
                        anomaly_score: 0.0,
                        reason: format!("grant '{}' matched", grant.resource),
                        limits: policy.limits.clone(),
                    };
                }
                Err(reason) => {
                    if policy.fail_open {
                        return PolicyResult {
                            allow: true,
                            policy_id: policy.id.clone(),
                            policy_version: policy.version,
                            policy_hash: Some(policy.content_hash()),
                            resource: ctx.resource.clone(),
                            anomaly_score: 1.0,
                            reason: format!("fail-open despite: {reason}"),
                            limits: policy.limits.clone(),
                        };
                    }
                    return PolicyResult::deny_for(policy, reason, &ctx.resource);
                }
            }
        }
    }
    PolicyResult::deny("no matching grant", &ctx.resource)
}

/// A grant allows a request when all constraints pass and its CEL condition (if any)
/// evaluates to `true`.
fn grant_allows(grant: &ResourceGrant, ctx: &PolicyContext) -> Result<(), String> {
    evaluate_constraints(&grant.constraints, &ctx.args)?;
    if let Some(condition) = &grant.condition {
        eval_condition(condition, ctx)?;
    }
    Ok(())
}

/// Compile and evaluate a CEL condition. Returns `Ok(())` when it is `true`, or an error
/// describing why the request should be denied.
pub fn eval_condition(expression: &str, ctx: &PolicyContext) -> Result<(), String> {
    let program = compiled(expression)?;

    let mut context = CelContext::default();
    add_string(&mut context, "resource", &ctx.resource)?;
    add_string(&mut context, "agent_id", &ctx.agent_id)?;
    add_string(&mut context, "user_id", &ctx.user_id)?;
    if let Value::Object(map) = &ctx.args {
        for (key, value) in map {
            let cel = to_cel(value)?;
            context
                .add_variable(key.clone(), cel)
                .map_err(|e| format!("cel variable '{key}': {e}"))?;
        }
    }

    // The interpreter is third-party code over tenant-supplied expressions: contain panics
    // and treat them as evaluation failures (deny-by-default, unless the policy fails open).
    let value =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| program.execute(&context)))
            .map_err(|_| "cel execute panic: interpreter rejected expression".to_string())?
            .map_err(|e| format!("cel execute error: {e}"))?;
    match value {
        CelValue::Bool(b) => {
            if b {
                Ok(())
            } else {
                Err("cel condition evaluated to false".to_string())
            }
        }
        other => Err(format!("cel condition must return a bool, got {other:?}")),
    }
}

/// Convert a JSON value into a CEL value.
fn to_cel(value: &Value) -> Result<CelValue, String> {
    Ok(match value {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                CelValue::UInt(u)
            } else {
                CelValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => CelValue::String(std::sync::Arc::new(s.clone())),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(to_cel(item)?);
            }
            CelValue::List(std::sync::Arc::new(out))
        }
        Value::Object(map) => {
            let mut out = HashMap::new();
            for (k, v) in map {
                out.insert(std::sync::Arc::new(k.clone()).into(), to_cel(v)?);
            }
            CelValue::Map(cel_interpreter::objects::Map {
                map: std::sync::Arc::new(out),
            })
        }
    })
}

fn add_string(context: &mut CelContext, name: &str, value: &str) -> Result<(), String> {
    context
        .add_variable(
            name.to_string(),
            CelValue::String(std::sync::Arc::new(value.to_string())),
        )
        .map_err(|e| format!("cel variable '{name}': {e}"))
}

#[derive(Clone)]
enum CachedProgram {
    Compiled(Arc<Program>),
    Failed(String),
}

fn program_cache() -> &'static Mutex<HashMap<String, CachedProgram>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedProgram>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Upper bound on memoized CEL programs. Expressions are tenant-supplied, so the cache must
/// be bounded; clearing it only costs recompilation.
const MAX_CACHED_PROGRAMS: usize = 4_096;

/// Poison-tolerant cache lock: a panic elsewhere must not brick policy evaluation.
fn cache_lock() -> std::sync::MutexGuard<'static, HashMap<String, CachedProgram>> {
    program_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Compile a CEL expression, memoizing the result (including compile failures).
///
/// The CEL parser can panic on malformed input instead of returning an error, so
/// compilation is contained in `catch_unwind` and a panic is treated as a compile error.
fn compiled(expression: &str) -> Result<Arc<Program>, String> {
    let cached_entry = cache_lock().get(expression).cloned();
    if let Some(entry) = cached_entry {
        return match &entry {
            CachedProgram::Compiled(program) => Ok(program.clone()),
            CachedProgram::Failed(err) => Err(err.clone()),
        };
    }

    let result: Result<Arc<Program>, String> =
        std::panic::catch_unwind(|| Program::compile(expression))
            .map_err(|_| "cel compile error: parser rejected expression".to_string())
            .and_then(|r| {
                r.map(Arc::new)
                    .map_err(|e| format!("cel compile error: {e}"))
            });

    let cached = match &result {
        Ok(program) => CachedProgram::Compiled(program.clone()),
        Err(err) => CachedProgram::Failed(err.clone()),
    };
    {
        let mut cache = cache_lock();
        if cache.len() >= MAX_CACHED_PROGRAMS {
            cache.clear();
        }
        cache.insert(expression.to_string(), cached);
    }
    result
}

/// Whether `pattern` grants `resource` (`*` and trailing-`*` prefixes are supported).
pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" || pattern == resource {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    false
}

fn evaluate_constraints(constraints: &[Constraint], args: &Value) -> Result<(), String> {
    for c in constraints {
        match c {
            Constraint::Required { field } => {
                if lookup(args, field).map(|v| v.is_null()).unwrap_or(true) {
                    return Err(format!("required field '{field}' missing"));
                }
            }
            Constraint::MaxNumber { field, value } => {
                let n = number(args, field)?;
                if n > *value {
                    return Err(format!("'{field}' = {n} exceeds max {value}"));
                }
            }
            Constraint::MinNumber { field, value } => {
                let n = number(args, field)?;
                if n < *value {
                    return Err(format!("'{field}' = {n} below min {value}"));
                }
            }
            Constraint::Allowlist { field, values } => {
                let s = string(args, field)?;
                if !values.iter().any(|v| v == &s) {
                    return Err(format!("'{field}' = '{s}' not in allowlist"));
                }
            }
            Constraint::Prefix { field, prefix } => {
                let s = string(args, field)?;
                if !s.starts_with(prefix) {
                    return Err(format!("'{field}' = '{s}' does not start with '{prefix}'"));
                }
            }
        }
    }
    Ok(())
}

/// Look up a (possibly dotted) field path in the arguments object.
fn lookup<'a>(args: &'a Value, field: &str) -> Option<&'a Value> {
    let mut cur = args;
    for part in field.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn number(args: &Value, field: &str) -> Result<f64, String> {
    lookup(args, field)
        .and_then(|v| v.as_f64())
        .ok_or_else(|| format!("field '{field}' is not a number"))
}

fn string(args: &Value, field: &str) -> Result<String, String> {
    lookup(args, field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("field '{field}' is not a string"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(resource: &str, args: Value) -> PolicyContext {
        PolicyContext {
            agent_id: "agent".into(),
            user_id: "user".into(),
            resource: resource.into(),
            args,
        }
    }

    fn policy(grants: Vec<ResourceGrant>) -> Policy {
        Policy {
            id: "p".into(),
            version: 3,
            name: "t".into(),
            grants,
            fail_open: false,
            limits: Default::default(),
        }
    }

    #[test]
    fn denies_when_no_grant() {
        let r = evaluate(&[policy(vec![])], &ctx("stripe:refunds.create", json!({})));
        assert!(!r.allow);
    }

    #[test]
    fn allows_matching_resource() {
        let p = policy(vec![ResourceGrant {
            resource: "stripe:refunds.create".into(),
            constraints: vec![],
            condition: None,
        }]);
        let r = evaluate(&[p], &ctx("stripe:refunds.create", json!({})));
        assert!(r.allow);
        assert_eq!(r.policy_version, 3);
    }

    #[test]
    fn wildcard_provider_prefix() {
        let p = policy(vec![ResourceGrant {
            resource: "stripe:*".into(),
            constraints: vec![],
            condition: None,
        }]);
        assert!(evaluate(&[p], &ctx("stripe:charges.create", json!({}))).allow);
    }

    #[test]
    fn max_number_blocks_large_amounts() {
        let p = policy(vec![ResourceGrant {
            resource: "stripe:refunds.create".into(),
            constraints: vec![Constraint::MaxNumber {
                field: "amount".into(),
                value: 5000.0,
            }],
            condition: None,
        }]);
        assert!(
            evaluate(
                std::slice::from_ref(&p),
                &ctx("stripe:refunds.create", json!({"amount": 4200}))
            )
            .allow
        );
        let r = evaluate(&[p], &ctx("stripe:refunds.create", json!({"amount": 9000})));
        assert!(!r.allow);
        assert!(r.reason.contains("exceeds max"));
    }

    #[test]
    fn allowlist_and_prefix() {
        let p = policy(vec![ResourceGrant {
            resource: "aws:s3:GetObject".into(),
            constraints: vec![
                Constraint::Allowlist {
                    field: "bucket".into(),
                    values: vec!["reports".into()],
                },
                Constraint::Prefix {
                    field: "key".into(),
                    prefix: "public/".into(),
                },
            ],
            condition: None,
        }]);
        assert!(
            evaluate(
                std::slice::from_ref(&p),
                &ctx(
                    "aws:s3:GetObject",
                    json!({"bucket":"reports","key":"public/a"})
                )
            )
            .allow
        );
        assert!(
            !evaluate(
                std::slice::from_ref(&p),
                &ctx(
                    "aws:s3:GetObject",
                    json!({"bucket":"secrets","key":"public/a"})
                )
            )
            .allow
        );
        assert!(
            !evaluate(
                &[p],
                &ctx(
                    "aws:s3:GetObject",
                    json!({"bucket":"reports","key":"private/a"})
                )
            )
            .allow
        );
    }

    #[test]
    fn nested_field_lookup() {
        let p = policy(vec![ResourceGrant {
            resource: "x".into(),
            constraints: vec![Constraint::MaxNumber {
                field: "a.b".into(),
                value: 1.0,
            }],
            condition: None,
        }]);
        assert!(evaluate(std::slice::from_ref(&p), &ctx("x", json!({"a": {"b": 0}}))).allow);
        assert!(!evaluate(&[p], &ctx("x", json!({"a": {"b": 2}}))).allow);
    }

    fn conditioned(resource: &str, condition: &str) -> Policy {
        policy(vec![ResourceGrant {
            resource: resource.into(),
            constraints: vec![],
            condition: Some(condition.into()),
        }])
    }

    #[test]
    fn cel_allows_when_true_and_denies_when_false() {
        let p = conditioned("stripe:refunds.create", "amount > 100");
        assert!(
            evaluate(
                std::slice::from_ref(&p),
                &ctx("stripe:refunds.create", json!({"amount": 150}))
            )
            .allow
        );
        let denied = evaluate(&[p], &ctx("stripe:refunds.create", json!({"amount": 50})));
        assert!(!denied.allow);
        assert!(denied.reason.contains("false"));
    }

    #[test]
    fn cel_list_membership() {
        let p = conditioned("x", r#"region in ["us", "eu"]"#);
        assert!(evaluate(std::slice::from_ref(&p), &ctx("x", json!({"region": "eu"}))).allow);
        assert!(!evaluate(&[p], &ctx("x", json!({"region": "apac"}))).allow);
    }

    #[test]
    fn cel_nested_and_builtin_variables() {
        let p = conditioned(
            "stripe:refunds.create",
            r#"user.role == "admin" && resource == "stripe:refunds.create""#,
        );
        assert!(
            evaluate(
                std::slice::from_ref(&p),
                &ctx("stripe:refunds.create", json!({"user": {"role": "admin"}}))
            )
            .allow
        );
        assert!(
            !evaluate(
                &[p],
                &ctx("stripe:refunds.create", json!({"user": {"role": "viewer"}}))
            )
            .allow
        );
    }

    #[test]
    fn cel_large_amount_example() {
        // The canonical "deny a huge refund" condition from the RFC.
        let p = conditioned(
            "stripe:refunds.create",
            "amount <= 5000 && currency == \"usd\"",
        );
        assert!(
            evaluate(
                std::slice::from_ref(&p),
                &ctx(
                    "stripe:refunds.create",
                    json!({"amount": 100, "currency": "usd"})
                )
            )
            .allow
        );
        assert!(
            !evaluate(
                &[p],
                &ctx(
                    "stripe:refunds.create",
                    json!({"amount": 100, "currency": "eur"})
                )
            )
            .allow
        );
    }

    #[test]
    fn cel_invalid_expression_denies() {
        let p = conditioned("x", "amount >");
        assert!(!evaluate(&[p], &ctx("x", json!({"amount": 1}))).allow);
    }

    #[test]
    fn cel_non_bool_denies() {
        let p = conditioned("x", "amount");
        let r = evaluate(&[p], &ctx("x", json!({"amount": 1})));
        assert!(!r.allow);
        assert!(r.reason.contains("must return a bool"));
    }

    #[test]
    fn cel_fail_open_overrides_condition_error() {
        let mut p = conditioned("x", "amount >");
        p.fail_open = true;
        assert!(evaluate(&[p], &ctx("x", json!({"amount": 1}))).allow);
    }

    #[test]
    fn cel_programs_are_cached() {
        let expression = "amount > 424242";
        let first = compiled(expression).unwrap();
        let second = compiled(expression).unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "second compile should hit the cache"
        );
    }

    #[test]
    fn cel_compile_failures_are_cached() {
        let expression = "this is not valid cel ===";
        let first = compiled(expression).unwrap_err();
        let second = compiled(expression).unwrap_err();
        assert_eq!(first, second);
        assert!(program_cache().lock().unwrap().contains_key(expression));
    }

    #[tokio::test]
    async fn policy_store_crud() {
        let store = InMemoryPolicyStore::new();
        assert!(store.list("t").await.unwrap().is_empty());
        assert!(store.get("t", "p").await.unwrap().is_none());

        store.upsert("t", policy(vec![])).await.unwrap();
        assert_eq!(store.list("t").await.unwrap().len(), 1);

        // Same id+version with different content must be rejected (history is immutable).
        let mut changed = policy(vec![]);
        changed.name = "changed".into();
        let err = store.upsert("t", changed).await.unwrap_err();
        assert!(matches!(err, BrokerError::Invalid(_)));

        // upsert with the same id replaces (no duplicate)
        let mut updated = policy(vec![]);
        updated.version = 9;
        store.upsert("t", updated).await.unwrap();
        assert_eq!(store.get("t", "p").await.unwrap().unwrap().version, 9);
        assert_eq!(store.list("t").await.unwrap().len(), 1);

        assert!(store.delete("t", "p").await.unwrap());
        assert!(!store.delete("t", "p").await.unwrap());
        assert!(store.list("t").await.unwrap().is_empty());
    }

    #[test]
    fn cel_cache_is_bounded_and_poison_tolerant() {
        // Fill beyond the cap with expressions that fail to compile (they are cached too).
        for index in 0..MAX_CACHED_PROGRAMS + 50 {
            let _ = compiled(&format!("not valid cel {{ {index} }}"));
        }
        assert!(cache_lock().len() <= MAX_CACHED_PROGRAMS);

        // A poisoned mutex must not brick evaluation: poison it, then compile again.
        let _ = std::thread::spawn(|| {
            let _guard = program_cache().lock().unwrap();
            panic!("poison the CEL cache");
        })
        .join();
        assert!(program_cache().is_poisoned());
        let result = compiled("1 + 1 == 2");
        assert!(
            result.is_ok(),
            "cache must recover from poisoning: {result:?}"
        );
    }
}
