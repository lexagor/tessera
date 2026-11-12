#![no_main]
//! Canonical JSON must be idempotent: canonicalize(parse(canonicalize(v))) == canonicalize(v).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let once = tessera_broker::canonical::canonicalize(&value);
            if let Ok(reparsed) = serde_json::from_str::<serde_json::Value>(&once) {
                let twice = tessera_broker::canonical::canonicalize(&reparsed);
                assert_eq!(once, twice, "canonicalization is not idempotent");
            }
        }
    }
});
