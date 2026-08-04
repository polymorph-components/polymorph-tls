//! The wasm-safe TLS 1.3 algorithm profile, as data.
//!
//! This crate is the single policy source for both of the profile's
//! deliveries (the component and the Rust guest library). It contains no
//! cryptography: the lists here name what the assembled stack
//! (`lann-tls-quic-crypto`) must ship, in the order it must prefer it, and
//! the identity types enforce the signing policy by API shape.
//!
//! See `README.md` for the profile document: the per-item timing classes,
//! their sources, and the rulings behind each list.

use std::fmt;
use std::sync::Arc;

use rustls::{CipherSuite, NamedGroup, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Cipher suites, in preference order.
///
/// ChaCha20-Poly1305 is preferred (class A/B). `TLS_AES_128_GCM_SHA256` is
/// present because RFC 8446 §9.1 makes it mandatory-to-implement; it must be
/// served only by a fixsliced, table-free AES (class C) and never preferred.
pub const CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
];

/// Key-exchange groups, in preference order.
///
/// X25519 preferred; secp256r1 present as RFC 8446 §9.1's MUST-support
/// curve. Both are class B via constant-time implementations.
pub const KEY_EXCHANGE_GROUPS: &[NamedGroup] = &[NamedGroup::X25519, NamedGroup::secp256r1];

/// Signature schemes the endpoint accepts in the peer's CertificateVerify
/// and certificate chain.
///
/// Verification is secret-free and therefore timing-class-exempt, so this
/// list carries the full RFC 8446 §9.1 mandatory-to-implement set plus
/// Ed25519 — breadth here costs nothing in the threat model.
pub const SIGNATURE_VERIFICATION_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// The signature scheme the endpoint may sign with in-guest.
///
/// Ed25519 signing is class B. ECDSA and RSA signing are class D and never
/// run in the guest; a WebPKI (ECDSA/RSA) identity requires an external
/// signer instead — see [`ServerIdentity::External`].
pub const IN_GUEST_SIGNING_SCHEME: SignatureScheme = SignatureScheme::ED25519;

/// An Ed25519 server identity: a certificate chain and the Ed25519 private
/// key that signs CertificateVerify in-guest.
///
/// The constructor accepts only Ed25519 key material. There is no way to
/// build an identity around an ECDSA or RSA private key: that material is
/// class D in wasm, and a deployment holding it must delegate signing via
/// [`ServerIdentity::External`] instead.
pub struct Ed25519Identity {
    chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
}

impl Ed25519Identity {
    /// Builds an identity from a certificate chain and a PKCS#8 v1/v2 DER
    /// document holding an Ed25519 private key.
    ///
    /// Fails if the document does not parse as an Ed25519 key — in
    /// particular, ECDSA and RSA PKCS#8 documents are rejected, they do not
    /// fall back to any other signing path.
    pub fn from_pkcs8_der(
        chain: Vec<CertificateDer<'static>>,
        pkcs8_der: &[u8],
    ) -> Result<Self, InvalidIdentity> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| InvalidIdentity(()))?;
        Ok(Self {
            chain,
            key_der: PrivateKeyDer::Pkcs8(pkcs8_der.to_vec().into()),
        })
    }

    /// The certificate chain, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The validated Ed25519 PKCS#8 key.
    pub fn key_der(&self) -> &PrivateKeyDer<'static> {
        &self.key_der
    }

    /// Consumes the identity.
    pub fn into_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.chain, self.key_der)
    }
}

impl fmt::Debug for Ed25519Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Identity")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// The key material was not an Ed25519 PKCS#8 document.
#[derive(Debug)]
pub struct InvalidIdentity(());

impl fmt::Display for InvalidIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key material is not an Ed25519 PKCS#8 document")
    }
}

impl std::error::Error for InvalidIdentity {}

/// A server identity under the profile's signing policy.
///
/// Signing the endpoint's own CertificateVerify is TLS 1.3's one
/// class-D-shaped operation. The two variants are the two postures the
/// profile permits:
///
/// - [`Ed25519`](ServerIdentity::Ed25519): the key is Ed25519 (class B) and
///   signs in-guest. Requires an Ed25519 certificate — in practice a
///   private PKI, since no public CA issues them.
/// - [`External`](ServerIdentity::External): the private key never enters
///   the guest; a caller-supplied signer produces the signature. This is
///   the posture for WebPKI (ECDSA/RSA) identities.
///
/// There is no third variant. In-guest ECDSA/RSA signing is not a
/// configuration this profile can express.
pub enum ServerIdentity {
    /// An Ed25519 identity signing in-guest.
    Ed25519(Ed25519Identity),
    /// A delegated signer; the implementation behind the trait object is
    /// the caller's responsibility and is expected to hold the private key
    /// outside the guest.
    External {
        /// The certificate chain, leaf first.
        chain: Vec<CertificateDer<'static>>,
        /// The signer for the leaf certificate's key.
        signer: Arc<dyn rustls::sign::SigningKey>,
    },
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(id) => f.debug_tuple("Ed25519").field(id).finish(),
            Self::External { chain, .. } => f
                .debug_struct("External")
                .field("chain_len", &chain.len())
                .finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the identity-key shape rule: an ECDSA PKCS#8 document must
    /// not build an [`Ed25519Identity`].
    #[test]
    fn rejects_non_ed25519_pkcs8() {
        // A P-256 PKCS#8 key (RFC 5958 structure, id-ecPublicKey).
        const P256_PKCS8: &[u8] = include_bytes!("testdata/p256-key.p8");
        assert!(Ed25519Identity::from_pkcs8_der(Vec::new(), P256_PKCS8).is_err());
    }

    #[test]
    fn accepts_ed25519_pkcs8() {
        const ED25519_PKCS8: &[u8] = include_bytes!("testdata/ed25519-key.p8");
        assert!(Ed25519Identity::from_pkcs8_der(Vec::new(), ED25519_PKCS8).is_ok());
    }
}
