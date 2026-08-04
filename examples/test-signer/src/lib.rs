//! A test implementation of `lann:tls/signer`.
//!
//! Holds the test fixture's Ed25519 key and signs CertificateVerify
//! messages with it — standing in, for composed smoke tests, for the
//! production shapes where the key lives outside the guest (a host
//! provider or a signing component). Not a shipped artifact.

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer as _, SigningKey};

wit_bindgen::generate!({
    path: "../../wit",
    inline: "
        package inline:signer;
        world signer-impl {
            export lann:tls/signer@0.1.0;
        }
    ",
    generate_all,
});

use exports::lann::tls::signer::{Guest, SignatureScheme};

const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf-key.p8");

struct Component;

export!(Component);

impl Guest for Component {
    async fn schemes() -> Vec<SignatureScheme> {
        vec![SignatureScheme::Ed25519]
    }

    async fn sign(scheme: SignatureScheme, message: Vec<u8>) -> Result<Vec<u8>, String> {
        if scheme != SignatureScheme::Ed25519 {
            return Err(format!("unsupported scheme: {scheme:?}"));
        }
        let key = SigningKey::from_pkcs8_der(LEAF_KEY_P8)
            .map_err(|e| format!("fixture key failed to parse: {e}"))?;
        Ok(key.sign(&message).to_bytes().to_vec())
    }
}
