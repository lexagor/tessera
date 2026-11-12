#![no_main]
//! Parsing arbitrary receipts and hashing/recovering must never panic.

use libfuzzer_sys::fuzz_target;
use tessera_broker::receipt::{recover, validate_v2, GrantReceipt};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(receipt) = serde_json::from_str::<GrantReceipt>(text) {
            let _ = tessera_broker::receipt::payload_hash_hex(&receipt);
            let _ = validate_v2(&receipt);
            let domain = tessera_broker::receipt::Domain::new(
                84532,
                "0x0000000000000000000000000000000000000000",
            )
            .unwrap();
            let _ = recover(&domain, &receipt);
        }
    }
});
