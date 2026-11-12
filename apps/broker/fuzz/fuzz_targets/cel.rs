#![no_main]
//! CEL evaluation must never panic, regardless of the expression.

use libfuzzer_sys::fuzz_target;
use serde_json::json;
use tessera_broker::policy::{eval_condition, PolicyContext};

fuzz_target!(|data: &[u8]| {
    if let Ok(expr) = std::str::from_utf8(data) {
        let ctx = PolicyContext {
            agent_id: "agent".into(),
            user_id: "user".into(),
            resource: "stripe:refunds.create".into(),
            args: json!({ "amount": 10, "currency": "usd", "user": { "role": "admin" } }),
        };
        let _ = eval_condition(expr, &ctx);
    }
});
