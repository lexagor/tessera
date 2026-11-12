//! Cross-language receipt hashing parity.
//!
//! The shared fixtures in `packages/receipt-schema/fixtures/` are hashed here (Rust) and in
//! `packages/receipt-schema/test/parity.test.ts` (TypeScript). Both must agree on the
//! canonical JSON and Keccak-256 payload hash.

use std::path::PathBuf;

use tessera_broker::receipt::{payload_hash_hex, GrantReceipt};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/receipt-schema/fixtures")
}

fn load_receipts() -> Vec<GrantReceipt> {
    let text = std::fs::read_to_string(fixtures_dir().join("receipts.json")).expect("fixtures");
    serde_json::from_str(&text).expect("parse fixtures")
}

#[test]
fn fixture_payload_hashes_match_expected() {
    let receipts = load_receipts();
    let expected: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("expected.json")).unwrap(),
    )
    .expect("parse expected");

    assert_eq!(
        receipts.len(),
        expected.len(),
        "fixture/expected length mismatch"
    );
    for (i, receipt) in receipts.iter().enumerate() {
        assert_eq!(
            payload_hash_hex(receipt).unwrap(),
            expected[i],
            "receipt {i}"
        );
    }
}

#[test]
fn fixture_tool_definition_hashes_match_expected() {
    use serde_json::Value;
    let definitions: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("tool-definitions.json")).unwrap(),
    )
    .expect("parse tool definitions");
    let expected: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("tool-expected.json")).unwrap(),
    )
    .expect("parse expected hashes");
    assert_eq!(definitions.len(), expected.len());
    for (i, definition) in definitions.iter().enumerate() {
        assert_eq!(
            tessera_broker::tool_pins::definition_hash(definition),
            expected[i],
            "tool definition {i}"
        );
    }
}

#[test]
fn integral_float_normalization() {
    use serde_json::json;
    use tessera_broker::canonical::canonicalize;
    assert_eq!(canonicalize(&json!({"a": 0.0})), r#"{"a":0}"#);
    assert_eq!(canonicalize(&json!({"a": 1.0})), r#"{"a":1}"#);
    assert_eq!(canonicalize(&json!({"a": 0.5})), r#"{"a":0.5}"#);
    assert_eq!(canonicalize(&json!({"a": 0.03})), r#"{"a":0.03}"#);
}
