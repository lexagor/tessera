//! Envelope encryption for secrets persisted by the broker (e.g. tenant anchor keys).
//!
//! Uses ChaCha20-Poly1305 with a 32-byte key from `TENANT_SECRET_ENC_KEY`. Ciphertexts are
//! self-describing (`enc:v1:` + base64(nonce ‖ ciphertext ‖ tag)) so plaintext values written
//! by older versions remain readable, and a wrong/missing key fails loudly instead of
//! silently returning garbage.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use crate::error::BrokerError;

const PREFIX: &str = "enc:v1:";
const NONCE_LEN: usize = 12;

/// Encrypts/decrypts small persisted secrets.
pub struct Envelope {
    cipher: ChaCha20Poly1305,
}

impl Envelope {
    /// Build from a 32-byte hex key.
    pub fn from_hex(key_hex: &str) -> Result<Self, BrokerError> {
        let bytes = hex::decode(key_hex.trim_start_matches("0x"))
            .map_err(|e| BrokerError::Invalid(format!("TENANT_SECRET_ENC_KEY hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(BrokerError::Invalid(format!(
                "TENANT_SECRET_ENC_KEY must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let key = chacha20poly1305::Key::try_from(&bytes[..])
            .map_err(|_| BrokerError::Invalid("TENANT_SECRET_ENC_KEY must be 32 bytes".into()))?;
        Ok(Self {
            cipher: ChaCha20Poly1305::new(&key),
        })
    }

    /// Encrypt a secret into a self-describing string.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, BrokerError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::try_from(&nonce_bytes[..])
            .map_err(|_| BrokerError::Internal("nonce construction failed".into()))?;
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| BrokerError::Internal("secret encryption failed".into()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(out)
        ))
    }

    /// Decrypt a value produced by [`Envelope::encrypt`].
    pub fn decrypt(&self, stored: &str) -> Result<String, BrokerError> {
        let body = stored
            .strip_prefix(PREFIX)
            .ok_or_else(|| BrokerError::Invalid("value is not envelope-encrypted".into()))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| BrokerError::Invalid(format!("bad ciphertext: {e}")))?;
        if raw.len() <= NONCE_LEN {
            return Err(BrokerError::Invalid("ciphertext too short".into()));
        }
        let nonce = Nonce::try_from(&raw[..NONCE_LEN])
            .map_err(|_| BrokerError::Invalid("nonce construction failed".into()))?;
        let plaintext = self
            .cipher
            .decrypt(&nonce, &raw[NONCE_LEN..])
            .map_err(|_| {
                BrokerError::Internal("secret decryption failed (wrong key or tampered)".into())
            })?;
        String::from_utf8(plaintext)
            .map_err(|e| BrokerError::Internal(format!("secret is not utf-8: {e}")))
    }
}

/// Whether a stored value is envelope-encrypted.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn round_trip_and_prefix() {
        let env = Envelope::from_hex(KEY).unwrap();
        let ct = env.encrypt("rk_live_secret_value").unwrap();
        assert!(is_encrypted(&ct));
        assert!(!ct.contains("rk_live_secret_value"));
        assert_eq!(env.decrypt(&ct).unwrap(), "rk_live_secret_value");
        // nonce randomization
        assert_ne!(ct, env.encrypt("rk_live_secret_value").unwrap());
    }

    #[test]
    fn wrong_key_fails_loudly() {
        let a = Envelope::from_hex(KEY).unwrap();
        let b = Envelope::from_hex(&"11".repeat(32)).unwrap();
        let ct = a.encrypt("secret").unwrap();
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let env = Envelope::from_hex(KEY).unwrap();
        let ct = env.encrypt("secret").unwrap();
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(ct.strip_prefix(PREFIX).unwrap())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        );
        assert!(env.decrypt(&tampered).is_err());
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(Envelope::from_hex("0x00").is_err());
        assert!(Envelope::from_hex("not-hex").is_err());
    }
}
