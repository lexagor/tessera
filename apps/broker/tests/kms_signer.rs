//! KMS/HSM-backed signing: receipt and anchor signing both go through the HTTP bridge.
//!
//! A mock KMS signs with a known local key; the broker must recover that key's address.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use tessera_broker::eth::{EthSigner, TxEip1559};
use tessera_broker::receipt::{
    new_receipt, recover, AuthorizationRef, CallRef, GrantRef, ReceiptSigner,
};
use tessera_broker::signer::{DigestSigner, HttpKmsSigner, LocalSigner};

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

async fn sign_handler(
    State(signer): State<Arc<LocalSigner>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let digest_hex = body["digest"].as_str().expect("digest");
    let raw = hex::decode(digest_hex.trim_start_matches("0x")).expect("hex");
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&raw);
    let (r, s, recid) = signer.sign_prehash(&digest).await.expect("sign");
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out.push(recid);
    Json(json!({
        "signature": format!("0x{}", hex::encode(out)),
        "address": signer.address_hex(),
    }))
}

async fn spawn_kms() -> String {
    let signer = Arc::new(LocalSigner::from_hex(TEST_KEY).unwrap());
    let app = Router::new()
        .route("/sign", post(sign_handler))
        .with_state(signer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn sample_receipt() -> tessera_broker::receipt::GrantReceipt {
    new_receipt(
        "acme",
        "agent-1",
        "user-1",
        tessera_broker::canonical::keccak256_str("intent"),
        AuthorizationRef {
            decision: "allow".into(),
            policy: "p".into(),
            policy_version: 1,
            resource: "stripe:refunds.create".into(),
            anomaly_score: 0.0,
            policy_hash: None,
        },
        CallRef {
            tool: "stripe.refunds.create".into(),
            args_hash: tessera_broker::canonical::keccak256_str("args"),
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

#[tokio::test]
async fn kms_backs_receipt_signing() {
    let base = spawn_kms().await;
    let expected = LocalSigner::from_hex(TEST_KEY).unwrap().address_hex();

    let signer = ReceiptSigner::with_backend(
        Arc::new(HttpKmsSigner::new(&base, &expected)),
        84532,
        ZERO_ADDR,
        true,
    )
    .unwrap();
    assert_eq!(signer.address_hex(), expected);

    let mut receipt = sample_receipt();
    signer.sign(&mut receipt).await.unwrap();
    assert!(receipt.signature.is_some());

    // the signature recovers to the KMS key's address
    assert_eq!(recover(signer.domain(), &receipt).unwrap(), expected);
}

#[tokio::test]
async fn kms_backs_anchor_signing() {
    let base = spawn_kms().await;
    let expected = LocalSigner::from_hex(TEST_KEY).unwrap().address_hex();

    let eth = EthSigner::from_backend(Arc::new(HttpKmsSigner::new(&base, &expected))).unwrap();
    assert_eq!(eth.address_hex(), expected);

    let raw = eth
        .sign_eip1559(&TxEip1559 {
            chain_id: 84532,
            nonce: 1,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: Some([0x11; 20]),
            value: 0,
            data: vec![],
        })
        .await
        .unwrap();
    assert!(raw.starts_with("0x02"), "typed transaction envelope");
}
