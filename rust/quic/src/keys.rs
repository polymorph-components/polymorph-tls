//! Endpoint-level keys quinn-proto requires from its crypto backend:
//! stateless-reset HMAC and retry-token protection.
//!
//! These mirror the constructions quinn's ring backend uses (HMAC-SHA-256
//! for reset tokens; HKDF-SHA-256 into AES-256-GCM for handshake tokens) so
//! tokens carry the same structure, just over RustCrypto implementations.

use aead::{AeadInOut, KeyInit};
use hmac::Mac;
use quinn_proto::crypto;
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
}

impl crypto::HandshakeTokenKey for TokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let mut key = [0u8; 32];
        self.0
            .expand(random_bytes, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Box::new(TokenAead(
            aes_gcm::Aes256Gcm::new_from_slice(&key).expect("invalid key length"),
        ))
    }
}

struct TokenAead(aes_gcm::Aes256Gcm);

// Tokens use a zero nonce: each AEAD key is derived fresh from random bytes,
// so the (key, nonce) pair is still unique per token.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

impl crypto::AeadKey for TokenAead {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), crypto::CryptoError> {
        self.0
            .encrypt_in_place(&ZERO_NONCE.into(), additional_data, data)
            .map_err(|_| crypto::CryptoError)
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], crypto::CryptoError> {
        let plain_len = data.len().checked_sub(16).ok_or(crypto::CryptoError)?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[plain_len..]);
        self.0
            .decrypt_inout_detached(
                &ZERO_NONCE.into(),
                additional_data,
                (&mut data[..plain_len]).into(),
                &tag.into(),
            )
            .map_err(|_| crypto::CryptoError)?;
        Ok(&mut data[..plain_len])
    }
}

#[cfg(test)]
mod tests {
    use quinn_proto::crypto::{HandshakeTokenKey, HmacKey};

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
    fn token_aead_roundtrip() {
        let key = TokenKey::new(b"master");
        let aead = key.aead_from_hkdf(b"randomness");
        let mut data = b"token contents".to_vec();
        aead.seal(&mut data, b"aad").unwrap();
        assert_ne!(&data[..], b"token contents");
        let plain = aead.open(&mut data, b"aad").unwrap();
        assert_eq!(plain, b"token contents");

        let mut data2 = b"token contents".to_vec();
        aead.seal(&mut data2, b"aad").unwrap();
        assert!(aead.open(&mut data2, b"bad aad").is_err());
    }
}
