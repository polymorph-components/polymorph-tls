//! quinn compatibility for the profile.
//!
//! The repository's primary artifact is TLS ([`lann_tls`] is the curated
//! core); this crate is the QUIC leg: everything quinn-proto needs to run
//! the profile's TLS 1.3 over QUIC, kept out of the core library's
//! dependency graph.
//!
//! - [`provider()`]: the profile provider with QUIC packet protection
//!   (RFC 9001) wired into both suites.
//! - [`client_config`] / [`server_config`]: rustls configs under that
//!   provider, with the early-data settings QUIC requires.
//! - [`QuicClientConfig`] / [`QuicServerConfig`]: quinn-proto
//!   `crypto::Session` implementations over those configs.
//! - [`ResetKey`] / [`TokenKey`]: the endpoint-level keys quinn-proto
//!   needs from its crypto backend.
//!
//! The same signing policy applies as in the core: the provider's key
//! loader accepts only Ed25519 keys, and server identities are
//! [`lann_tls_profile::ServerIdentity`].

mod keys;
mod packet;
mod session;
mod suites;

use std::fmt;
use std::sync::Arc;

use lann_tls_profile::ServerIdentity;
use rustls::crypto::{CryptoProvider, KeyProvider};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls_pki_types::PrivateKeyDer;

pub use keys::{ResetKey, TokenKey};
pub use session::{HandshakeData, NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
pub use suites::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};

/// The profile's `CryptoProvider` with QUIC support.
///
/// Identical policy to `lann_tls::provider()` — profile suites and groups
/// in preference order, secret-free verification breadth, Ed25519-only key
/// loading — but every suite carries RFC 9001 packet protection, which
/// rustls requires for QUIC connections.
pub fn provider() -> Arc<CryptoProvider> {
    let base = rustls_rustcrypto::provider();
    let kx_groups = lann_tls_profile::KEY_EXCHANGE_GROUPS
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards provider/profile agreement: same policy as the core
    /// provider, QUIC wiring aside.
    #[test]
    fn provider_matches_profile() {
        let provider = provider();
        let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(suites, lann_tls_profile::CIPHER_SUITES);
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, lann_tls_profile::KEY_EXCHANGE_GROUPS);
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
