//! Deterministic canonical JSON and Keccak-256 hashing.
//!
//! The canonical form sorts object keys and emits no insignificant whitespace. It must
//! match `packages/receipt-schema` (TypeScript) so that receipts hash identically across
//! languages.

use serde_json::Value;
use sha3::{Digest, Keccak256};

/// Canonicalize a JSON value: sorted keys, compact output.
pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => canonical_number(n),
        Value::String(s) => serde_json::to_string(s).expect("string serialization cannot fail"),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let key = serde_json::to_string(k).expect("key serialization cannot fail");
                    let value = map.get(k).expect("key came from the map");
                    format!("{}:{}", key, canonicalize(value))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Canonical number formatting, shared across languages.
///
/// Integral floats are emitted without a fractional part (`0.0` -> `0`) so Rust's `ryu`
/// output matches JavaScript's `Number.prototype.toString`. Non-integral numbers use the
/// shortest round-trip representation in both languages.
fn canonical_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 {
            return (f as i64).to_string();
        }
        // serde_json uses ryu (shortest round-trip), as does JS `Number::toString`.
        return n.to_string();
    }
    n.to_string()
}

/// Keccak-256 of arbitrary bytes, hex-encoded with a `0x` prefix.
pub fn keccak256_hex(bytes: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Keccak-256 of a UTF-8 string.
pub fn keccak256_str(s: &str) -> String {
    keccak256_hex(s.as_bytes())
}

/// Hash a JSON value by its canonical form. Used for `args_hash` and `payload_hash`.
pub fn hash_json(value: &Value) -> String {
    keccak256_str(&canonicalize(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_keys() {
        let a = canonicalize(&json!({"b": 1, "a": 2}));
        let b = canonicalize(&json!({"a": 2, "b": 1}));
        assert_eq!(a, b);
        assert_eq!(a, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonicalize_nested_and_arrays() {
        let v = json!({"z": [3, {"y": 1, "x": 2}], "a": "s"});
        assert_eq!(canonicalize(&v), r#"{"a":"s","z":[3,{"x":2,"y":1}]}"#);
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_json(&json!({"amount": 100, "currency": "usd"}));
        let h2 = hash_json(&json!({"currency": "usd", "amount": 100}));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn keccak_known_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            keccak256_str(""),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
