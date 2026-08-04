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
        ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|_| InvalidIdentity("key material is not an Ed25519 PKCS#8 document"))?;
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

/// The key material cannot serve as a profile identity.
#[derive(Debug)]
pub struct InvalidIdentity(&'static str);

impl fmt::Display for InvalidIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
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

// --- Raw public keys (RFC 7250) ---

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410,
/// algorithm 1.3.101.112). The 32-byte public key follows it.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Encodes an Ed25519 public key as a DER `SubjectPublicKeyInfo` — the
/// bytes a raw-public-key "certificate" carries on the wire.
pub fn ed25519_spki(public_key: &[u8; 32]) -> Vec<u8> {
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(public_key);
    spki
}

/// The Ed25519 public key inside a DER `SubjectPublicKeyInfo`, if it is
/// one. Use this to read a peer's authenticated key out of a
/// raw-public-key "certificate".
pub fn public_key_from_ed25519_spki(spki: &[u8]) -> Option<[u8; 32]> {
    let (prefix, key) = spki.split_at_checked(ED25519_SPKI_PREFIX.len())?;
    if prefix != ED25519_SPKI_PREFIX {
        return None;
    }
    key.try_into().ok()
}

/// A raw-public-key identity (RFC 7250): a bare Ed25519 key whose public
/// half *is* the endpoint's identity.
///
/// Raw public keys are the profile's peer-to-peer posture: no chain, no
/// PKI — a verified connection authenticates possession of the private
/// key behind the presented public key, nothing else. The same identity
/// type serves both roles; under this posture connections are mutually
/// authenticated, so clients sign CertificateVerify too, governed by the
/// same signing policy as servers:
///
/// - [`from_pkcs8_der`](Self::from_pkcs8_der): an Ed25519 key (class B)
///   signing in-guest.
/// - [`external`](Self::external): a caller-supplied signer holding the
///   key elsewhere.
///
/// The profile's raw-public-key identities are Ed25519 only; there is no
/// way to build one around another algorithm.
pub struct RpkIdentity {
    public_key: [u8; 32],
    signer: RpkSignerInner,
}

enum RpkSignerInner {
    Ed25519 {
        key_der: PrivateKeyDer<'static>,
    },
    External {
        signer: Arc<dyn rustls::sign::SigningKey>,
    },
}

/// A borrowed view of how an [`RpkIdentity`] signs, for the delivery
/// crates that assemble rustls configurations from it.
pub enum RpkSigner<'a> {
    /// A validated Ed25519 PKCS#8 document; signing runs in-guest.
    Ed25519Pkcs8(&'a PrivateKeyDer<'static>),
    /// A caller-supplied signer; the private key lives behind it.
    External(&'a Arc<dyn rustls::sign::SigningKey>),
}

impl RpkIdentity {
    /// Builds an identity from a PKCS#8 v1/v2 DER document holding an
    /// Ed25519 private key; the public key is derived from it.
    ///
    /// Fails if the document does not parse as an Ed25519 key — ECDSA and
    /// RSA documents are rejected, they do not fall back to any other
    /// signing path.
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, InvalidIdentity> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let key = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|_| InvalidIdentity("key material is not an Ed25519 PKCS#8 document"))?;
        Ok(Self {
            public_key: key.verifying_key().to_bytes(),
            signer: RpkSignerInner::Ed25519 {
                key_der: PrivateKeyDer::Pkcs8(pkcs8_der.to_vec().into()),
            },
        })
    }

    /// Builds an identity around a caller-supplied signer whose private
    /// key lives elsewhere (typically outside the guest).
    ///
    /// The signer must report its public key
    /// ([`SigningKey::public_key`](rustls::sign::SigningKey::public_key))
    /// as an Ed25519 `SubjectPublicKeyInfo`; anything else is rejected.
    pub fn external(signer: Arc<dyn rustls::sign::SigningKey>) -> Result<Self, InvalidIdentity> {
        let spki = signer
            .public_key()
            .ok_or(InvalidIdentity("signer does not expose its public key"))?;
        let public_key = public_key_from_ed25519_spki(spki.as_ref()).ok_or(InvalidIdentity(
            "signer's public key is not an Ed25519 SPKI",
        ))?;
        Ok(Self {
            public_key,
            signer: RpkSignerInner::External { signer },
        })
    }

    /// The identity's Ed25519 public key — the value a peer authenticates.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The identity's public key as the DER `SubjectPublicKeyInfo` it
    /// presents on the wire.
    pub fn spki_der(&self) -> Vec<u8> {
        ed25519_spki(&self.public_key)
    }

    /// How this identity signs.
    pub fn signer(&self) -> RpkSigner<'_> {
        match &self.signer {
            RpkSignerInner::Ed25519 { key_der } => RpkSigner::Ed25519Pkcs8(key_der),
            RpkSignerInner::External { signer } => RpkSigner::External(signer),
        }
    }
}

impl fmt::Debug for RpkIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpkIdentity")
            .field("public_key", &self.public_key)
            .field(
                "signer",
                match self.signer {
                    RpkSignerInner::Ed25519 { .. } => &"Ed25519",
                    RpkSignerInner::External { .. } => &"External",
                },
            )
            .finish()
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

    /// The same shape rule holds for raw-public-key identities.
    #[test]
    fn rpk_rejects_non_ed25519_pkcs8() {
        const P256_PKCS8: &[u8] = include_bytes!("testdata/p256-key.p8");
        assert!(RpkIdentity::from_pkcs8_der(P256_PKCS8).is_err());
    }

    #[test]
    fn rpk_public_key_roundtrips_through_spki() {
        const ED25519_PKCS8: &[u8] = include_bytes!("testdata/ed25519-key.p8");
        let identity = RpkIdentity::from_pkcs8_der(ED25519_PKCS8).unwrap();
        let spki = identity.spki_der();
        assert_eq!(
            public_key_from_ed25519_spki(&spki),
            Some(identity.public_key()),
        );
        // A P-256 SPKI (or any non-Ed25519 DER) does not parse.
        assert_eq!(public_key_from_ed25519_spki(&spki[1..]), None);
        assert_eq!(public_key_from_ed25519_spki(b"not spki"), None);
    }
}
