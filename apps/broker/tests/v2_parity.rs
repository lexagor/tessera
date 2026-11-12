//! Cross-language v2 fixture: a record signed by the TypeScript verifier test key must
//! hash and recover identically in Rust. This catches EIP-712 drift between languages.

use std::path::PathBuf;

use tessera_broker::receipt::{payload_hash_hex, recover, Domain, GrantReceipt};
use tessera_broker::verify::verify_receipt;

fn fixture() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/receipt-schema/fixtures/receipt-v2-signed.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json")
}

#[test]
fn ts_signed_v2_fixture_verifies_in_rust() {
    let value = fixture();
    let receipt: GrantReceipt = serde_json::from_value(value["receipt"].clone()).expect("receipt");
    let expected_signer = value["expectedSigner"].as_str().expect("expectedSigner");
    let expected_hash = value["expectedPayloadHash"]
        .as_str()
        .expect("expectedPayloadHash");

    assert_eq!(payload_hash_hex(&receipt).unwrap(), expected_hash);

    let chain_id = value["domain"]["chainId"].as_u64().expect("chainId");
    let contract = value["domain"]["verifyingContract"]
        .as_str()
        .expect("verifyingContract");
    let domain = Domain::new(chain_id, contract).expect("domain");
    let result = verify_receipt(&domain, &receipt, Some(expected_signer)).expect("verify");
    assert!(result.valid);
    assert_eq!(result.matches_expected, Some(true));
    assert_eq!(result.recovered, expected_signer);
}

#[test]
fn high_s_signatures_are_rejected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/receipt-schema/fixtures/receipt-v2-highs.json");
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json");
    let receipt: GrantReceipt = serde_json::from_value(value["receipt"].clone()).expect("receipt");
    let chain_id = value["domain"]["chainId"].as_u64().expect("chainId");
    let contract = value["domain"]["verifyingContract"]
        .as_str()
        .expect("verifyingContract");
    let domain = Domain::new(chain_id, contract).expect("domain");
    let err = recover(&domain, &receipt).expect_err("high-S must be rejected");
    assert!(err.to_string().contains("low-S"), "{err}");
}
