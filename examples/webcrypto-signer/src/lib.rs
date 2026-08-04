//! Adapts a `lann:webcrypto` signing provider to `lann:tls/signer`.
//!
//! The TLS identity's Ed25519 private key lives behind a webcrypto
//! `signing-key` handle — in whatever the composed provider is (in-guest
//! component, host provider) — and never enters this component either:
//! this shim moves the CertificateVerify message in and the signature
//! out.
//!
//! Key provisioning is fixture-based for the composed smoke rig: the
//! shim imports the test key into the provider on each use. A production
//! shim would acquire its key handle by deployment-specific means; the
//! adaptation logic is unchanged by that.

use futures::join;

wit_bindgen::generate!({
    path: "wit",
    world: "shim",
    generate_all,
});

use exports::lann::tls::signer::{Guest, SignatureScheme};
use lann::webcrypto::ed25519_sign;
use lann::webcrypto::signature::SigningKeyOptions;

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

        let options = SigningKeyOptions::new();
        options.can_sign(true);
        let key = ed25519_sign::import_signing_key_pkcs8(LEAF_KEY_P8.to_vec(), options)
            .await
            .map_err(|e| format!("webcrypto key import failed: {e:?}"))?;

        let (mut tx, rx) = wit_stream::new();
        let sign = key.sign(rx);
        let write = async move {
            let leftover = tx.write_all(message).await;
            assert!(leftover.is_empty());
            drop(tx);
        };
        let (signature, ()) = join!(sign, write);
        signature.map_err(|e| format!("webcrypto signing failed: {e:?}"))
    }
}
