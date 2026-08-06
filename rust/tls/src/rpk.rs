//! Raw-public-key TLS (RFC 7250): mutually authenticated connections
//! where a bare Ed25519 public key is the peer's identity.
//!
//! This is the profile's peer-to-peer posture, and it changes what a
//! completed handshake means. **A verified connection authenticates
//! possession of the private key behind the presented public key —
//! nothing else.** There are no names, no chains, no expiry, and no
//! revocation. The two verification policies here are the two that make
//! sense under that model:
//!
//! - Outgoing ([`client_config`]): the caller already knows which key it
//!   intends to reach, and the connection fails unless the server proves
//!   exactly that key ([`RpkServerVerifier`]).
//! - Incoming ([`server_config`]): any client proving possession of a
//!   well-formed Ed25519 key is admitted ([`RpkClientVerifier`]), and the
//!   application reads the authenticated key afterward
//!   ([`peer_public_key`]) to decide what it may do. Skipping that read
//!   makes the server effectively unauthenticated — admission is not
//!   authorization.
//!
//! Both directions present an identity and sign CertificateVerify: see
//! [`RpkIdentity`] for the signing postures. Everything in this module
//! stays within the profile's timing classes (Ed25519 verification is
//! secret-free; signing is class B in-guest or delegated).
//!
//! Interoperability: RFC 7250 requires support on both peers (rustls,
//! OpenSSL 3.2+, GnuTLS, wolfSSL — not BoringSSL, Go, browsers, or
//! platform TLS stacks). It is a controlled-both-ends deployment shape,
//! not a WebPKI substitute, and it is specific to this in-process
//! delivery: host-terminated TLS providers generally cannot serve it.
//!
//! The server name on outgoing connections is ignored by
//! [`RpkServerVerifier`] (identity lives in the key pin); use any
//! syntactically valid placeholder name.

use std::sync::Arc;

use polymorph_tls_profile::{public_key_from_ed25519_spki, RpkIdentity, RpkSigner};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};

/// A TLS 1.3-only client config authenticating as `identity` and
/// requiring the server to prove possession of exactly
/// `expected_server_key`.
///
/// ALPN is left to the caller (set `alpn_protocols` on the returned
/// config).
pub fn client_config(
    identity: &RpkIdentity,
    expected_server_key: &[u8; 32],
) -> Result<rustls::ClientConfig, Error> {
    let provider = crate::provider();
    let algorithms = provider.signature_verification_algorithms;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RpkServerVerifier::new(
            expected_server_key,
            algorithms,
        )))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
            certified_key(identity)?,
        )))))
}

/// A TLS 1.3-only server config authenticating as `identity` and
/// requiring clients to prove possession of an Ed25519 raw public key.
///
/// Read the authenticated client key with [`peer_public_key`] after the
/// handshake; admission alone authorizes nothing. ALPN is left to the
/// caller.
pub fn server_config(identity: &RpkIdentity) -> Result<rustls::ServerConfig, Error> {
    let provider = crate::provider();
    let algorithms = provider.signature_verification_algorithms;
    Ok(rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .with_client_cert_verifier(Arc::new(RpkClientVerifier::new(algorithms)))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            certified_key(identity)?,
        )))))
}

/// The rustls `CertifiedKey` presenting `identity`: its SPKI as the sole
/// "certificate", signing per the identity's posture.
///
/// This is the building block for assembling raw-public-key configs by
/// hand; prefer [`client_config`]/[`server_config`].
pub fn certified_key(identity: &RpkIdentity) -> Result<CertifiedKey, Error> {
    let signer = match identity.signer() {
        RpkSigner::Ed25519Pkcs8(key_der) => rustls_rustcrypto::sign::any_eddsa_type(key_der)?,
        RpkSigner::External(signer) => signer.clone(),
    };
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(identity.spki_der())],
        signer,
    ))
}

/// The peer's authenticated Ed25519 key from the raw-public-key
/// "certificate" it presented (e.g. the first element of
/// `peer_certificates()`).
///
/// On a completed connection made with this module's configs, the peer
/// has proven possession of this key's private half.
pub fn peer_public_key(peer_certificate: &CertificateDer<'_>) -> Option<[u8; 32]> {
    public_key_from_ed25519_spki(peer_certificate.as_ref())
}

/// Verifies the server side of a raw-public-key connection: the presented
/// key must be exactly the expected one, proven by its Ed25519 handshake
/// signature.
#[derive(Debug)]
pub struct RpkServerVerifier {
    expected_spki: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl RpkServerVerifier {
    /// A verifier accepting only `expected_key`, verifying signatures
    /// with `algorithms` (use the profile provider's).
    pub fn new(expected_key: &[u8; 32], algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self {
            expected_spki: polymorph_tls_profile::ed25519_spki(expected_key),
            algorithms,
        }
    }
}

impl ServerCertVerifier for RpkServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(CertificateError::BadEncoding.into());
        }
        if end_entity.as_ref() != self.expected_spki {
            return Err(CertificateError::ApplicationVerificationFailure.into());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(rustls::PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Verifies the client side of a raw-public-key connection: any
/// well-formed Ed25519 key is admitted once its handshake signature
/// proves possession. Client authentication is mandatory — a connection
/// without a client key does not complete.
#[derive(Debug)]
pub struct RpkClientVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl RpkClientVerifier {
    /// A verifier admitting any proven Ed25519 key, verifying signatures
    /// with `algorithms` (use the profile provider's).
    pub fn new(algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self { algorithms }
    }
}

impl ClientCertVerifier for RpkClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(CertificateError::BadEncoding.into());
        }
        if public_key_from_ed25519_spki(end_entity.as_ref()).is_none() {
            return Err(CertificateError::BadEncoding.into());
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(rustls::PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_PKCS8: &[u8] = include_bytes!("../../profile/src/testdata/ed25519-key.p8");

    fn identity() -> RpkIdentity {
        RpkIdentity::from_pkcs8_der(ED25519_PKCS8).unwrap()
    }

    fn verify_args() -> (ServerName<'static>, UnixTime) {
        (
            ServerName::try_from("rpk.invalid").unwrap(),
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(0)),
        )
    }

    /// The pin admits exactly the expected key.
    #[test]
    fn server_verifier_pins_the_key() {
        let identity = identity();
        let algorithms = crate::provider().signature_verification_algorithms;
        let verifier = RpkServerVerifier::new(&identity.public_key(), algorithms);
        let (name, now) = verify_args();

        let presented = CertificateDer::from(identity.spki_der());
        assert!(verifier
            .verify_server_cert(&presented, &[], &name, &[], now)
            .is_ok());

        let mut wrong = identity.public_key();
        wrong[0] ^= 1;
        let presented = CertificateDer::from(polymorph_tls_profile::ed25519_spki(&wrong));
        assert!(verifier
            .verify_server_cert(&presented, &[], &name, &[], now)
            .is_err());
    }

    /// The client verifier admits well-formed Ed25519 keys and nothing
    /// else.
    #[test]
    fn client_verifier_requires_ed25519_spki() {
        let identity = identity();
        let algorithms = crate::provider().signature_verification_algorithms;
        let verifier = RpkClientVerifier::new(algorithms);
        let (_, now) = verify_args();

        let presented = CertificateDer::from(identity.spki_der());
        assert!(verifier.verify_client_cert(&presented, &[], now).is_ok());
        // An X.509 certificate is not a raw public key.
        let cert =
            CertificateDer::from(include_bytes!("../../quic/tests/testdata/leaf.der").to_vec());
        assert!(verifier.verify_client_cert(&cert, &[], now).is_err());
        // Intermediates are structurally impossible under RFC 7250.
        let presented = CertificateDer::from(identity.spki_der());
        let extra = presented.clone();
        assert!(verifier
            .verify_client_cert(&presented, &[extra], now)
            .is_err());
    }

    /// Both configs assemble under the profile provider.
    #[test]
    fn configs_build() {
        let identity = identity();
        let peer_key = identity.public_key();
        assert!(client_config(&identity, &peer_key).is_ok());
        assert!(server_config(&identity).is_ok());
    }
}
