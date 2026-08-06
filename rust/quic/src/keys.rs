//! Endpoint-level keys noq-proto requires from its crypto backend:
//! stateless-reset HMAC and retry-token protection.
//!
//! These mirror the constructions noq's ring backend uses (HMAC-SHA-256
//! for reset tokens; HKDF-SHA-256 into AES-256-GCM for handshake tokens)
//! so tokens carry the same structure, just over RustCrypto
//! implementations.

use aead::{AeadInOut, KeyInit};
use hmac::Mac;
use noq_proto::crypto;
use sha2::Sha256;

type HmacSha256 = hmac::Hmac<Sha256>;

/// An HMAC-SHA-256 key, for `EndpointConfig::new` (stateless reset tokens).
pub struct ResetKey(HmacSha256);

impl ResetKey {
    /// Builds the key from secret bytes.
    pub fn new(secret: &[u8]) -> Self {
        Self(HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length"))
    }
}

impl crypto::HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut mac = self.0.clone();
        mac.update(data);
        signature_out.copy_from_slice(&mac.finalize().into_bytes());
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::CryptoError> {
        let mut mac = self.0.clone();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| crypto::CryptoError)
    }
}

/// An HKDF-SHA-256 pseudorandom key, for `ServerConfig` retry/NEW_TOKEN
/// protection.
pub struct TokenKey(hkdf::Hkdf<Sha256>);

impl TokenKey {
    /// Extracts the key from secret bytes (no salt).
    pub fn new(master_secret: &[u8]) -> Self {
        Self(hkdf::Hkdf::new(None, master_secret))
    }

    /// The per-token AEAD: a fresh AES-256-GCM key expanded from the
    /// token nonce. A zero AEAD nonce is sound because each (key, nonce)
    /// pair is unique per token.
    fn derive_aead(&self, token_nonce: u128) -> aes_gcm::Aes256Gcm {
        let mut key = [0u8; 32];
        self.0
            .expand(&token_nonce.to_le_bytes(), &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        aes_gcm::Aes256Gcm::new_from_slice(&key).expect("invalid key length")
    }
}

const ZERO_NONCE: [u8; 12] = [0u8; 12];

impl crypto::HandshakeTokenKey for TokenKey {
    fn seal(&self, token_nonce: u128, data: &mut Vec<u8>) -> Result<(), crypto::CryptoError> {
        self.derive_aead(token_nonce)
            .encrypt_in_place(&ZERO_NONCE.into(), &[], data)
            .map_err(|_| crypto::CryptoError)
    }

    fn open<'a>(
        &self,
        token_nonce: u128,
        data: &'a mut [u8],
    ) -> Result<&'a [u8], crypto::CryptoError> {
        let plain_len = data.len().checked_sub(16).ok_or(crypto::CryptoError)?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[plain_len..]);
        self.derive_aead(token_nonce)
            .decrypt_inout_detached(
                &ZERO_NONCE.into(),
                &[],
                (&mut data[..plain_len]).into(),
                &tag.into(),
            )
            .map_err(|_| crypto::CryptoError)?;
        Ok(&data[..plain_len])
    }
}

#[cfg(test)]
mod tests {
    use noq_proto::crypto::{HandshakeTokenKey, HmacKey};

    use super::*;

    #[test]
    fn reset_key_roundtrip() {
        let key = ResetKey::new(b"some secret");
        let mut sig = [0u8; 32];
        key.sign(b"payload", &mut sig);
        assert!(key.verify(b"payload", &sig).is_ok());
        assert!(key.verify(b"other payload", &sig).is_err());
    }

    #[test]
    fn token_roundtrip() {
        let key = TokenKey::new(b"master");
        let mut data = b"token contents".to_vec();
        key.seal(7, &mut data).unwrap();
        assert_ne!(&data[..], b"token contents");
        let plain = key.open(7, &mut data).unwrap();
        assert_eq!(plain, b"token contents");

        let mut data2 = b"token contents".to_vec();
        key.seal(7, &mut data2).unwrap();
        assert!(key.open(8, &mut data2).is_err());
    }
}
