#![no_main]
//! Every leaf's inclusion proof must verify against the tree root.

use libfuzzer_sys::fuzz_target;
use tessera_broker::merkle::{self, MerkleTree};

fuzz_target!(|data: &[u8]| {
    let leaves: Vec<[u8; 32]> = data
        .chunks_exact(32)
        .map(|chunk| {
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(chunk);
            leaf
        })
        .collect();

    let tree = MerkleTree::new(leaves.clone());
    let root = tree.root();
    for (i, leaf) in leaves.iter().enumerate() {
        assert!(merkle::verify(&tree.proof(i), root, *leaf), "proof failed at {i}");
    }
});
