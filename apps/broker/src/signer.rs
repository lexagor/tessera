//! Pluggable prehash signing: an in-process key or an external KMS/HSM over HTTP.
//!
//! Both receipt signing (EIP-712) and anchor transaction signing (EIP-1559) go through this
//! interface, so the key never has to live in the broker process.

use std::sync::Arc;

use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;

/// Signs a 32-byte digest. Returns `(r, s, recovery_id)` with `recovery_id ∈ {0, 1}`.
#[async_trait]
pub trait DigestSigner: Send + Sync {
    fn address_hex(&self) -> String;
    async fn sign_prehash(
        &self,
        digest: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], u8), BrokerError>;
}

/// Ethereum-style address (last 20 bytes of `keccak(uncompressed_pubkey[1..])`).
pub fn address_of(vk: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let hash = crate::merkle::keccak(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

pub fn address_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

// ── In-process signer ───────────────────────────────────────────────────────

pub struct LocalSigner {
    key: SigningKey,
    address: [u8; 20],
}

impl LocalSigner {
    pub fn from_hex(key_hex: &str) -> Result<Self, BrokerError> {
        let bytes = hex::decode(key_hex.trim_start_matches("0x"))
            .map_err(|e| BrokerError::Invalid(format!("bad signing key: {e}")))?;
        let key = SigningKey::from_slice(&bytes)
            .map_err(|e| BrokerError::Invalid(format!("invalid signing key: {e}")))?;
        let address = address_of(key.verifying_key());
        Ok(Self { key, address })
    }

    pub fn random() -> Self {
        let key = SigningKey::random(&mut rand::thread_rng());
        let address = address_of(key.verifying_key());
        Self { key, address }
    }

    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    /// The private key as `0x`-prefixed hex. Only for key-management tooling (`tessera-keygen`);
    /// never log or serialize this in server paths.
    pub fn private_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.key.to_bytes()))
    }
}

#[async_trait]
impl DigestSigner for LocalSigner {
    fn address_hex(&self) -> String {
        address_hex(&self.address)
    }

    async fn sign_prehash(
        &self,
        digest: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], u8), BrokerError> {
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|e| BrokerError::Receipt(format!("signing failed: {e}")))?;
        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok((r, s, recid.to_byte()))
    }
}

// ── HTTP KMS/HSM bridge ─────────────────────────────────────────────────────

/// Signs via an external service: `POST {url}/sign {"digest":"0x…"}` ->
/// `{"signature":"0x<r||s||v>","address":"0x…"}` with `v ∈ {0,1,27,28}`.
pub struct HttpKmsSigner {
    url: String,
    address: String,
    http: reqwest::Client,
}

impl HttpKmsSigner {
    pub fn new(url: &str, address: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            address: address.to_string(),
            http: crate::netguard::outbound_client(),
        }
    }
}

#[derive(Deserialize)]
struct KmsResponse {
    signature: String,
    /// Optional; if the bridge returns its signer address it is ignored (the configured
    /// `KMS_SIGNER_ADDRESS` is authoritative for `address_hex`).
    #[serde(default)]
    #[allow(dead_code)]
    address: Option<String>,
}

#[async_trait]
impl DigestSigner for HttpKmsSigner {
    fn address_hex(&self) -> String {
        self.address.clone()
    }

    async fn sign_prehash(
        &self,
        digest: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], u8), BrokerError> {
        let body = json!({ "digest": format!("0x{}", hex::encode(digest)) });
        let resp = self
            .http
            .post(format!("{}/sign", self.url))
            .json(&body)
            .send()
            .await
            .map_err(|e| BrokerError::Receipt(format!("kms request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(BrokerError::Receipt(format!(
                "kms returned {}",
                resp.status()
            )));
        }
        let parsed: KmsResponse = resp
            .json()
            .await
            .map_err(|e| BrokerError::Receipt(format!("kms response parse failed: {e}")))?;
        let raw = hex::decode(parsed.signature.trim_start_matches("0x"))
            .map_err(|e| BrokerError::Receipt(format!("kms signature hex: {e}")))?;
        if raw.len() != 65 {
            return Err(BrokerError::Receipt(format!(
                "kms signature must be 65 bytes, got {}",
                raw.len()
            )));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..64]);
        let v = raw[64];
        let recid = if v >= 27 { v - 27 } else { v };
        Ok((r, s, recid))
    }
}

/// Build the configured backend: KMS bridge if `KMS_SIGNER_URL` is set, else a local key.
pub fn backend_from_config(
    kms_url: Option<&str>,
    kms_address: Option<&str>,
    local_key_hex: Option<&str>,
) -> Result<Arc<dyn DigestSigner>, BrokerError> {
    if let Some(url) = kms_url {
        return Ok(Arc::new(HttpKmsSigner::new(
            url,
            kms_address.unwrap_or_default(),
        )));
    }
    match local_key_hex {
        Some(hex) if !hex.trim_start_matches("0x").chars().all(|c| c == '0') && !hex.is_empty() => {
            Ok(Arc::new(LocalSigner::from_hex(hex)?))
        }
        _ => Ok(Arc::new(LocalSigner::random())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_signer_matches_known_address() {
        let signer = LocalSigner::from_hex(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        assert_eq!(
            signer.address_hex(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );

        let digest = [7u8; 32];
        let (r, s, recid) = signer.sign_prehash(&digest).await.unwrap();
        assert!(recid <= 1);
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
        let rec = k256::ecdsa::RecoveryId::from_byte(recid).unwrap();
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &sig, rec).unwrap();
        assert_eq!(address_hex(&address_of(&vk)), signer.address_hex());
    }
}
