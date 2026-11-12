use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;

use tessera_broker::canonical;
use tessera_broker::policy::{
    evaluate, Constraint, Policy, PolicyContext, PolicyLimits, PolicyMode, ResourceGrant,
};
use tessera_broker::receipt::{
    new_receipt, payload_hash_hex, AuthorizationRef, CallRef, GrantRef, ReceiptSigner,
};

const KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO: &str = "0x0000000000000000000000000000000000000000";

fn policy() -> Policy {
    Policy {
        id: "bench".into(),
        version: 1,
        name: "Benchmark policy".into(),
        grants: vec![ResourceGrant {
            resource: "stripe:refunds.create".into(),
            constraints: vec![Constraint::MaxNumber {
                field: "amount".into(),
                value: 500.0,
            }],
            condition: Some("amount < 500 && resource == \"stripe:refunds.create\"".into()),
        }],
        fail_open: false,
        mode: PolicyMode::Enforce,
        limits: PolicyLimits::default(),
    }
}

fn context() -> PolicyContext {
    PolicyContext {
        agent_id: "billing-agent".into(),
        user_id: "user-1".into(),
        resource: "stripe:refunds.create".into(),
        args: json!({ "amount": 100, "charge": "ch_bench" }),
    }
}

fn sample_receipt() -> tessera_broker::receipt::GrantReceipt {
    new_receipt(
        "acme",
        "billing-agent",
        "user-1",
        canonical::keccak256_str("refund a duplicate charge"),
        AuthorizationRef {
            decision: "allow".into(),
            policy: "bench".into(),
            policy_version: 1,
            resource: "stripe:refunds.create".into(),
            anomaly_score: 0.0,
            policy_hash: Some(canonical::keccak256_str("policy")),
        },
        CallRef {
            tool: "stripe.refunds.create".into(),
            args_hash: canonical::hash_json(&json!({ "amount": 100, "charge": "ch_bench" })),
            result_hash: None,
            tool_hash: None,
        },
        GrantRef {
            provider: "stripe".into(),
            ttl_s: 30,
            single_use: true,
            status: "issued".into(),
        },
    )
}

fn bench_policy(c: &mut Criterion) {
    let policies = vec![policy()];
    let ctx = context();
    c.bench_function("policy/evaluate_constraints_and_cel", |b| {
        b.iter(|| evaluate(black_box(&policies), black_box(&ctx)));
    });
}

fn bench_canonical(c: &mut Criterion) {
    let args = json!({
        "amount": 100,
        "charge": "ch_bench",
        "metadata": { "customer": "cus_1", "region": "us" },
        "items": [1, 2, 3, 4, 5],
    });
    c.bench_function("canonical/hash_json", |b| {
        b.iter(|| canonical::hash_json(black_box(&args)));
    });
}

fn bench_receipt(c: &mut Criterion) {
    let signer = ReceiptSigner::from_hex_or_random(Some(KEY), 84532, ZERO).unwrap();
    let base = sample_receipt();
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("receipt/payload_hash", |b| {
        b.iter(|| payload_hash_hex(black_box(&base)));
    });
    c.bench_function("receipt/eip712_sign", |b| {
        b.iter(|| {
            let mut receipt = base.clone();
            rt.block_on(signer.sign(black_box(&mut receipt))).unwrap();
            black_box(receipt.signature);
        });
    });
}

criterion_group!(benches, bench_policy, bench_canonical, bench_receipt);
criterion_main!(benches);
