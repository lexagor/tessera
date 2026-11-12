//! Randomized property tests: no panics, stable canonicalization, sound Merkle proofs,
//! safe CEL evaluation, and RLP length-prefix boundaries.

use serde_json::{json, Map, Value};
use tessera_broker::canonical::canonicalize;
use tessera_broker::eth::{minimal_be, Rlp};
use tessera_broker::merkle::{hash_pair, keccak, MerkleTree};
use tessera_broker::policy::{eval_condition, PolicyContext};

/// Deterministic xorshift64 PRNG (no external deps).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

fn random_scalar(rng: &mut Rng) -> Value {
    match rng.below(5) {
        0 => json!(rng.below(1000)),
        1 => json!(format!("s{}", rng.below(100))),
        2 => json!(rng.below(2) == 0),
        3 => Value::Null,
        _ => json!((rng.below(1000) as f64) / 10.0),
    }
}

fn random_object(rng: &mut Rng, keys: u64, depth: u64) -> Value {
    let mut map = Map::new();
    for i in 0..keys {
        let key = format!("k{i}");
        let value = if depth > 0 && rng.below(4) == 0 {
            let n = rng.below(3) + 1;
            random_object(rng, n, depth - 1)
        } else {
            random_scalar(rng)
        };
        map.insert(key, value);
    }
    Value::Object(map)
}

#[test]
fn canonicalization_is_order_independent_and_idempotent() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..200 {
        let keys = rng.below(6) + 1;
        let value = random_object(&mut rng, keys, 2);

        let once = canonicalize(&value);
        let twice = canonicalize(&serde_json::from_str::<Value>(&once).unwrap());
        assert_eq!(once, twice, "canonicalize must be idempotent");

        // Rebuild the object with keys inserted in a different order.
        let mut shuffled = Map::new();
        let mut entries: Vec<(&String, &Value)> = value.as_object().unwrap().iter().collect();
        // deterministic shuffle
        for i in (1..entries.len()).rev() {
            let j = rng.below((i + 1) as u64) as usize;
            entries.swap(i, j);
        }
        for (k, v) in entries {
            shuffled.insert(k.clone(), v.clone());
        }
        assert_eq!(once, canonicalize(&Value::Object(shuffled)));
    }
}

#[test]
fn merkle_proofs_verify_for_random_trees() {
    let mut rng = Rng(0xdead_beef_0bad_f00d);
    for _ in 0..100 {
        let count = rng.below(64) as usize;
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|_| keccak(&rng.next().to_be_bytes()))
            .collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            assert!(
                tessera_broker::merkle::verify(&tree.proof(i), root, *leaf),
                "proof failed for tree of {count}, index {i}"
            );
        }

        if count > 0 {
            let tampered = [0xABu8; 32];
            let i = rng.below(count as u64) as usize;
            assert!(!tessera_broker::merkle::verify(
                &tree.proof(i),
                root,
                tampered
            ));
        }
    }
}

#[test]
fn hash_pair_is_commutative() {
    let a = keccak(b"a");
    let b = keccak(b"b");
    assert_eq!(hash_pair(a, b), hash_pair(b, a));
}

#[test]
fn cel_random_expressions_never_panic() {
    let charset: Vec<char> = "abc0123 ()<>=+*/!\"'&|in".chars().collect();
    let ctx = PolicyContext {
        agent_id: "a".into(),
        user_id: "u".into(),
        resource: "r".into(),
        args: json!({"amount": 10, "currency": "usd"}),
    };
    let mut rng = Rng(0x0f0f_0f0f_0f0f_0f0f);
    for _ in 0..2_000 {
        let len = rng.below(24) as usize;
        let expr: String = (0..len)
            .map(|_| charset[rng.below(charset.len() as u64) as usize])
            .collect();
        // Must return Ok or Err, never unwind.
        let _ = eval_condition(&expr, &ctx);
    }
}

#[test]
fn rlp_length_prefix_boundaries() {
    let short = vec![0u8; 55];
    assert_eq!(Rlp::Bytes(&short).encode()[0], 0x80 + 55);
    let long = vec![0u8; 56];
    assert_eq!(Rlp::Bytes(&long).encode()[0], 0xb8);
    assert_eq!(Rlp::Bytes(&long).encode()[1], 56);
}

#[test]
fn minimal_be_roundtrips() {
    let mut rng = Rng(0xabcdef01_23456789);
    for _ in 0..1_000 {
        let n = rng.next() as u128;
        let bytes = minimal_be(n);
        assert!(bytes.is_empty() || bytes[0] != 0, "no leading zero bytes");
        if !bytes.is_empty() {
            let value = bytes.iter().fold(0u128, |acc, b| (acc << 8) | *b as u128);
            assert_eq!(value, n);
        } else {
            assert_eq!(n, 0);
        }
    }
}
