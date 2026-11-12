//! Independent verification of receipts, chains, and Merkle proofs.
//!
//! These functions need only the EIP-712 [`Domain`] (chain id + verifying contract), not
//! the broker's signing key or any broker state. They are exposed publicly so a receipt can
//! be checked without trusting the broker.

use serde::{Deserialize, Serialize};

use crate::chain::ChainEntry;
use crate::error::BrokerError;
use crate::receipt::{self, Domain, GrantReceipt};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptVerification {
    pub valid: bool,
    pub recovered: String,
    pub payload_hash: String,
    /// Present only when the caller supplies `expectedSigner`.
    pub matches_expected: Option<bool>,
}

/// Upper bound on entries/proofs accepted by the verification functions: verification is
/// public and CPU-bound, so unbounded input is a denial-of-service vector.
pub const MAX_VERIFY_ENTRIES: usize = 1_000;
/// A Merkle proof for 2^64 leaves is 64 hashes; anything longer is malformed.
pub const MAX_MERKLE_PROOF: usize = 64;

pub fn verify_receipt(
    domain: &Domain,
    receipt: &GrantReceipt,
    expected_signer: Option<&str>,
) -> Result<ReceiptVerification, BrokerError> {
    if receipt::validate_v2(receipt).is_err() {
        return Ok(ReceiptVerification {
            valid: false,
            recovered: String::new(),
            payload_hash: String::new(),
            matches_expected: None,
        });
    }
    let recovered = match receipt::recover(domain, receipt) {
        Ok(recovered) => recovered,
        Err(_) => {
            return Ok(ReceiptVerification {
                valid: false,
                recovered: String::new(),
                payload_hash: receipt::payload_hash_hex(receipt).unwrap_or_default(),
                matches_expected: None,
            })
        }
    };
    let payload_hash = receipt::payload_hash_hex(receipt)?;
    let matches_expected = expected_signer.map(|e| recovered.eq_ignore_ascii_case(e));
    Ok(ReceiptVerification {
        valid: true,
        recovered,
        payload_hash,
        matches_expected,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerification {
    pub valid: bool,
    pub length: usize,
    pub recovered: Option<String>,
}

/// Verify a chain: every entry's stored `payload_hash` must match its receipt, every
/// signature must recover, and every `prev` link must line up. All receipts must share one
/// signer.
pub fn verify_chain(
    domain: &Domain,
    entries: &[ChainEntry],
) -> Result<ChainVerification, BrokerError> {
    if entries.len() > MAX_VERIFY_ENTRIES {
        return Err(BrokerError::Invalid(format!(
            "too many entries: {} (max {MAX_VERIFY_ENTRIES})",
            entries.len()
        )));
    }
    if entries.is_empty() {
        return Ok(ChainVerification {
            valid: false,
            length: 0,
            recovered: None,
        });
    }
    let mut prev: Option<String> = None;
    let mut recovered: Option<String> = None;

    for entry in entries {
        if receipt::validate_v2(&entry.receipt).is_err() {
            return Ok(ChainVerification {
                valid: false,
                length: entries.len(),
                recovered: None,
            });
        }
        let computed = receipt::payload_hash_hex(&entry.receipt)?;
        if computed != entry.payload_hash {
            return Ok(ChainVerification {
                valid: false,
                length: entries.len(),
                recovered: None,
            });
        }
        let address = match receipt::recover(domain, &entry.receipt) {
            Ok(addr) => addr,
            Err(_) => {
                return Ok(ChainVerification {
                    valid: false,
                    length: entries.len(),
                    recovered: None,
                })
            }
        };
        match &recovered {
            Some(first) if !address.eq_ignore_ascii_case(first) => {
                return Ok(ChainVerification {
                    valid: false,
                    length: entries.len(),
                    recovered: None,
                })
            }
            None => recovered = Some(address),
            _ => {}
        }
        if entry.receipt.prev != prev {
            return Ok(ChainVerification {
                valid: false,
                length: entries.len(),
                recovered: None,
            });
        }
        prev = Some(entry.payload_hash.clone());
    }

    Ok(ChainVerification {
        valid: true,
        length: entries.len(),
        recovered,
    })
}

/// Verify a Merkle inclusion proof using the contract's sorted-pair convention.
pub fn verify_merkle(root: &str, leaf: &str, proof: &[String]) -> Result<bool, BrokerError> {
    if proof.len() > MAX_MERKLE_PROOF {
        return Err(BrokerError::Invalid(format!(
            "merkle proof too long: {} (max {MAX_MERKLE_PROOF})",
            proof.len()
        )));
    }
    let root = decode32(root)?;
    let leaf = decode32(leaf)?;
    let mut siblings = Vec::with_capacity(proof.len());
    for item in proof {
        siblings.push(decode32(item)?);
    }
    Ok(crate::merkle::verify(&siblings, root, leaf))
}

fn decode32(value: &str) -> Result<[u8; 32], BrokerError> {
    let raw = hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Invalid(format!("bad hex32: {e}")))?;
    if raw.len() != 32 {
        return Err(BrokerError::Invalid(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical;
    use crate::receipt::{new_receipt, AuthorizationRef, CallRef, GrantRef, ReceiptSigner};

    const KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const ZERO: &str = "0x0000000000000000000000000000000000000000";

    fn signer() -> ReceiptSigner {
        ReceiptSigner::from_hex_or_random(Some(KEY), 84532, ZERO).unwrap()
    }

    async fn receipt(agent: &str) -> GrantReceipt {
        let mut r = new_receipt(
            "acme",
            agent,
            "u",
            canonical::keccak256_str("intent"),
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
                args_hash: canonical::keccak256_str("args"),
                result_hash: None,
                tool_hash: None,
            },
            GrantRef {
                provider: "stripe".into(),
                ttl_s: 30,
                single_use: true,
                status: "issued".into(),
            },
        );
        signer().sign(&mut r).await.unwrap();
        r
    }

    #[test]
    fn empty_chain_is_invalid() {
        let domain = *signer().domain();
        let result = verify_chain(&domain, &[]).unwrap();
        assert!(!result.valid);
    }

    #[tokio::test]
    async fn verifies_without_the_key() {
        let s = signer();
        let domain = *s.domain();
        let r = receipt("a1").await;
        let result = verify_receipt(&domain, &r, Some(&s.address_hex())).unwrap();
        assert!(result.valid);
        assert_eq!(result.matches_expected, Some(true));
        assert_eq!(result.recovered, s.address_hex());
    }

    #[tokio::test]
    async fn detects_tampering() {
        let s = signer();
        let domain = *s.domain();
        let mut r = receipt("a1").await;
        r.call.args_hash = canonical::keccak256_str("evil");
        // signature no longer matches
        assert!(
            receipt::recover(&domain, &r).is_err() || {
                let other = verify_receipt(&domain, &r, Some(&s.address_hex())).unwrap();
                other.matches_expected == Some(false) || !other.valid
            }
        );
    }

    #[test]
    fn merkle_proof_verifies() {
        use crate::merkle::{keccak, MerkleTree};
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| keccak(format!("l{i}").as_bytes())).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = format!("0x{}", hex::encode(tree.root()));
        let leaf = format!("0x{}", hex::encode(leaves[2]));
        let proof: Vec<String> = tree
            .proof(2)
            .iter()
            .map(|p| format!("0x{}", hex::encode(p)))
            .collect();
        assert!(verify_merkle(&root, &leaf, &proof).unwrap());
        assert!(!verify_merkle(
            &root,
            &format!("0x{}", hex::encode(keccak(b"evil"))),
            &proof
        )
        .unwrap());
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;
    use crate::receipt::{Domain, GrantReceipt};

    fn domain() -> Domain {
        Domain::new(84532, "0x0000000000000000000000000000000000000000").unwrap()
    }

    #[test]
    fn oversized_chain_is_rejected_before_work() {
        let entries = vec![
            ChainEntry {
                payload_hash: "0x00".into(),
                receipt: GrantReceipt {
                    v: 1,
                    tenant: "t".into(),
                    agent: "a".into(),
                    user: "u".into(),
                    intent_hash: "0x00".into(),
                    authorization: crate::receipt::AuthorizationRef {
                        decision: "allow".into(),
                        policy: "p".into(),
                        policy_version: 1,
                        resource: "r".into(),
                        anomaly_score: 0.0,
                        policy_hash: None,
                    },
                    call: crate::receipt::CallRef {
                        tool: "t".into(),
                        args_hash: "0x00".into(),
                        result_hash: None,
                        tool_hash: None,
                    },
                    grant: crate::receipt::GrantRef {
                        provider: "p".into(),
                        ttl_s: 1,
                        single_use: true,
                        status: "issued".into(),
                    },
                    ts: "2026-01-01T00:00:00Z".into(),
                    nonce: "0x00".into(),
                    prev: None,
                    authorization_receipt_id: None,
                    signature: None,
                    action_id: None,
                    principal: None,
                    agent_meta: None,
                    intent: None,
                    policy: None,
                    credential: None,
                    outcome: None,
                    attestation: None,
                },
            };
            MAX_VERIFY_ENTRIES + 1
        ];
        let err = verify_chain(&domain(), &entries).unwrap_err();
        assert!(matches!(err, BrokerError::Invalid(_)));
    }

    #[test]
    fn oversized_merkle_proof_is_rejected() {
        let proof = vec!["0x00".to_string(); MAX_MERKLE_PROOF + 1];
        let err = verify_merkle(&"0x00".repeat(32), &"0x00".repeat(32), &proof).unwrap_err();
        assert!(matches!(err, BrokerError::Invalid(_)));
    }
}
