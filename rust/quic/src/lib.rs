//! QUIC crypto for the profile, over noq-proto.
//!
//! The repository's primary artifact is TLS ([`polymorph_tls`] is the curated
//! core); this crate is the QUIC leg: everything noq-proto needs to run
//! the profile's TLS 1.3 over QUIC, kept out of the core library's
//! dependency graph.
//!
//! - [`provider()`]: the profile provider with QUIC packet protection
//!   (RFC 9001, plus the multipath nonce construction noq-proto's paths
//!   use) wired into both suites.
//! - [`client_config`] / [`server_config`]: rustls configs under that
//!   provider, with the early-data settings QUIC requires.
//! - [`QuicClientConfig`] / [`QuicServerConfig`]: noq-proto's own
//!   provider-agnostic `crypto::Session` glue, re-exported; it takes the
//!   initial suite from the config's provider.
//! - [`ResetKey`] / [`TokenKey`]: the endpoint-level keys noq-proto
//!   needs from its crypto backend.
//!
//! The same signing policy applies as in the core: the provider's key
//! loader accepts only Ed25519 keys, and server identities are
//! [`polymorph_tls_profile::ServerIdentity`].

mod keys;
mod packet;
mod suites;

use std::fmt;
use std::sync::Arc;

use polymorph_tls_profile::ServerIdentity;
use rustls::crypto::{CryptoProvider, KeyProvider};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls_pki_types::PrivateKeyDer;

pub use keys::{ResetKey, TokenKey};
pub use noq_proto::crypto::rustls::{
    HandshakeData, NoInitialCipherSuite, QuicClientConfig, QuicServerConfig,
};
pub use suites::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};

/// The profile's `CryptoProvider` with QUIC support.
///
/// Identical policy to `polymorph_tls::provider()` — profile suites and groups
/// in preference order, secret-free verification breadth, Ed25519-only key
/// loading — but every suite carries RFC 9001 packet protection, which
/// rustls requires for QUIC connections.
pub fn provider() -> Arc<CryptoProvider> {
    let base = rustls_rustcrypto::provider();
    let kx_groups = polymorph_tls_profile::KEY_EXCHANGE_GROUPS
        .iter()
        .map(|group| {
            *base
                .kx_groups
                .iter()
                .find(|kx| kx.name() == *group)
                .expect("rustls-rustcrypto provides every profile key-exchange group")
        })
        .collect();
    Arc::new(CryptoProvider {
        cipher_suites: vec![TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256],
        kx_groups,
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: base.secure_random,
        key_provider: &ED25519_ONLY,
    })
}

static ED25519_ONLY: Ed25519OnlyKeyProvider = Ed25519OnlyKeyProvider;

#[derive(Debug)]
struct Ed25519OnlyKeyProvider;

impl KeyProvider for Ed25519OnlyKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        rustls_rustcrypto::sign::any_eddsa_type(&key_der)
    }
}

/// A QUIC-ready client config: TLS 1.3 only, early data enabled (0-RTT).
///
/// `alpn` is required: QUIC mandates ALPN (RFC 9001 §8.1), and rustls
/// refuses QUIC handshakes without it.
pub fn client_config(roots: rustls::RootCertStore, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.enable_early_data = true;
    config
}

/// A QUIC-ready server config: TLS 1.3 only, 0-RTT accepted
/// (`max_early_data_size` is `u32::MAX`, the only nonzero value QUIC
/// permits).
///
/// `alpn` is required: QUIC mandates ALPN (RFC 9001 §8.1), and rustls
/// refuses QUIC handshakes without it.
pub fn server_config(
    identity: ServerIdentity,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, rustls::Error> {
    let builder = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .with_no_client_auth();
    let mut config = match identity {
        ServerIdentity::Ed25519(identity) => {
            let (chain, key) = identity.into_parts();
            builder.with_single_cert(chain, key)?
        }
        ServerIdentity::External { chain, signer } => builder.with_cert_resolver(Arc::new(
            StaticResolver(Arc::new(CertifiedKey::new(chain, signer))),
        )),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = u32::MAX;
    Ok(config)
}

struct StaticResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl fmt::Debug for StaticResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticResolver").finish_non_exhaustive()
    }
}

/// A QUIC-ready raw-public-key client config (RFC 7250): mutually
/// authenticated, pinning the server to `expected_server_key`.
///
/// See [`polymorph_tls::rpk`] for the trust contract — a verified connection
/// authenticates key possession, nothing else. `alpn` is required
/// (RFC 9001 §8.1).
pub fn rpk_client_config(
    identity: &polymorph_tls_profile::RpkIdentity,
    expected_server_key: &[u8; 32],
    alpn: &[&[u8]],
) -> Result<rustls::ClientConfig, rustls::Error> {
    use rustls::client::AlwaysResolvesClientRawPublicKeys;

    let provider = provider();
    let algorithms = provider.signature_verification_algorithms;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(polymorph_tls::rpk::RpkServerVerifier::new(
            expected_server_key,
            algorithms,
        )))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
            polymorph_tls::rpk::certified_key(identity)?,
        ))));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.enable_early_data = true;
    Ok(config)
}

/// A QUIC-ready raw-public-key server config (RFC 7250): mutually
/// authenticated, admitting any client that proves an Ed25519 key.
///
/// Read the authenticated client key with [`polymorph_tls::rpk::peer_public_key`]
/// after the handshake; admission is not authorization. `alpn` is
/// required (RFC 9001 §8.1).
pub fn rpk_server_config(
    identity: &polymorph_tls_profile::RpkIdentity,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, rustls::Error> {
    use rustls::server::AlwaysResolvesServerRawPublicKeys;

    let provider = provider();
    let algorithms = provider.signature_verification_algorithms;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .with_client_cert_verifier(Arc::new(polymorph_tls::rpk::RpkClientVerifier::new(
            algorithms,
        )))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            polymorph_tls::rpk::certified_key(identity)?,
        ))));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = u32::MAX;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards provider/profile agreement: same policy as the core
    /// provider, QUIC wiring aside.
    #[test]
    fn provider_matches_profile() {
        let provider = provider();
        let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(suites, polymorph_tls_profile::CIPHER_SUITES);
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, polymorph_tls_profile::KEY_EXCHANGE_GROUPS);
    }

    /// Guards the class-D key rejection in the QUIC provider too.
    #[test]
    fn key_provider_rejects_ecdsa() {
        let p256 = include_bytes!("../../profile/src/testdata/p256-key.p8");
        let key = PrivateKeyDer::Pkcs8(p256.to_vec().into());
        assert!(provider().key_provider.load_private_key(key).is_err());
    }

    /// Every suite in the QUIC provider must carry RFC 9001 support.
    #[test]
    fn suites_are_quic_capable() {
        for suite in provider().cipher_suites.iter() {
            let tls13 = suite.tls13().expect("profile suites are TLS 1.3");
            assert!(
                tls13.quic_suite().is_some(),
                "{:?} lacks QUIC",
                suite.suite()
            );
        }
    }
}
