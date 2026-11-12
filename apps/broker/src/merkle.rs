//! Merkle batching for receipt anchoring.
//!
//! Leaves are receipt `payload_hash` values. Internal nodes hash their children in
//! ascending byte order (`keccak(min ‖ max)`), which is exactly the convention used by
//! `ReceiptAnchor._verify`, so proofs produced here verify on-chain.

use sha3::{Digest, Keccak256};

use crate::error::BrokerError;
use crate::receipt::GrantReceipt;

/// keccak256 helper returning raw bytes.
pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&lo);
    buf[32..].copy_from_slice(&hi);
    keccak(&buf)
}

/// Leaf for a receipt (its payload hash).
pub fn leaf_for_receipt(receipt: &GrantReceipt) -> Result<[u8; 32], BrokerError> {
    crate::receipt::payload_hash(receipt)
}

pub struct MerkleTree {
    /// `levels[0]` are the leaves; the last level contains a single root.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        let mut levels = vec![leaves];
        while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let current = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(hash_pair(current[i], current[i + 1]));
                } else {
                    next.push(current[i]); // carry an odd node up unchanged
                }
                i += 2;
            }
            levels.push(next);
        }
        Self { levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    /// Inclusion proof for `index` (sibling hashes from leaf to root).
    pub fn proof(&self, index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sibling = idx ^ 1;
            if sibling < level.len() {
                proof.push(level[sibling]);
            }
            idx /= 2;
        }
        proof
    }
}

/// Verify a proof. Matches `ReceiptAnchor._verify`.
pub fn verify(proof: &[[u8; 32]], root: [u8; 32], leaf: [u8; 32]) -> bool {
    let mut computed = leaf;
    for sibling in proof {
        computed = hash_pair(computed, *sibling);
    }
    computed == root
}

/// A batch of receipt leaves ready to be anchored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorBatch {
    pub root: String,
    pub count: u64,
    pub leaves: Vec<String>,
    pub calldata: String,
    pub proof: Vec<String>,
}

/// Build an anchor batch (root + ready-to-submit calldata + the last leaf's proof).
pub fn build_batch(tenant: [u8; 32], leaves: Vec<[u8; 32]>) -> AnchorBatch {
    let tree = MerkleTree::new(leaves.clone());
    let root = tree.root();
    let proof = if leaves.is_empty() {
        Vec::new()
    } else {
        tree.proof(leaves.len() - 1)
    };
    AnchorBatch {
        root: hex32(&root),
        count: leaves.len() as u64,
        leaves: leaves.iter().map(hex32).collect(),
        calldata: anchor_calldata(tenant, root, leaves.len() as u64),
        proof: proof.iter().map(hex32).collect(),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// ABI-encode a call to `ReceiptAnchor.anchor(bytes32 tenant, bytes32 merkleRoot, uint64 count)`.
pub fn anchor_calldata(tenant: [u8; 32], root: [u8; 32], count: u64) -> String {
    let selector = &keccak(b"anchor(bytes32,bytes32,uint64)")[..4];
    let mut count_word = [0u8; 32];
    count_word[24..].copy_from_slice(&count.to_be_bytes());

    let mut data = Vec::with_capacity(4 + 96);
    data.extend_from_slice(selector);
    data.extend_from_slice(&tenant);
    data.extend_from_slice(&root);
    data.extend_from_slice(&count_word);
    format!("0x{}", hex::encode(data))
}

/// keccak256("anchor(bytes32,bytes32,uint64)")[0..4].
pub fn anchor_selector() -> String {
    format!(
        "0x{}",
        hex::encode(&keccak(b"anchor(bytes32,bytes32,uint64)")[..4])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(s: &str) -> [u8; 32] {
        keccak(s.as_bytes())
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let tree = MerkleTree::new(vec![leaf("a")]);
        assert_eq!(tree.root(), leaf("a"));
        assert!(tree.proof(0).is_empty());
        assert!(verify(&[], tree.root(), leaf("a")));
    }

    #[test]
    fn empty_tree_root_is_zero() {
        let tree = MerkleTree::new(vec![]);
        assert_eq!(tree.root(), [0u8; 32]);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn pair_is_order_independent() {
        let a = leaf("a");
        let b = leaf("b");
        assert_eq!(hash_pair(a, b), hash_pair(b, a));
        let tree = MerkleTree::new(vec![b, a]);
        assert_eq!(tree.root(), hash_pair(a, b));
    }

    #[test]
    fn proofs_verify_for_all_leaves() {
        for n in 1..=9usize {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| leaf(&format!("leaf-{i}"))).collect();
            let tree = MerkleTree::new(leaves.clone());
            let root = tree.root();
            for (i, l) in leaves.iter().enumerate() {
                assert!(verify(&tree.proof(i), root, *l), "n={n} index={i}");
            }
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| leaf(&format!("leaf-{i}"))).collect();
        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        assert!(!verify(&tree.proof(0), root, leaf("evil")));
    }

    /// Cross-language anchor: this root is recomputed independently in
    /// `contracts/receipts/test/ReceiptAnchor.t.sol` (`test_cross_language_root`).
    /// Cross-language anchor: this root is recomputed independently in
    /// `contracts/receipts/test/ReceiptAnchor.t.sol` (`test_cross_language_root`).
    #[test]
    fn cross_language_root_matches_solidity() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| keccak(format!("receipt-{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::new(leaves);
        assert_eq!(
            hex32(&tree.root()),
            "0x9b273f5e529ec8c336d2e2f6a1b4cf3703f0ae1c460cad01a1b1851d870c22e5"
        );
    }

    #[test]
    fn anchor_selector_matches_contract() {
        assert_eq!(anchor_selector(), "0x15954b2c");
    }

    #[test]
    fn calldata_has_selector_and_args() {
        let tenant = keccak(b"acme");
        let root = keccak(b"root");
        let calldata = anchor_calldata(tenant, root, 7);
        // 4-byte selector + 3 * 32-byte words
        assert_eq!(calldata.len(), 2 + (4 + 96) * 2);
        assert!(calldata.starts_with("0x15954b2c"));
        assert_eq!(anchor_selector(), "0x15954b2c");
    }
}
