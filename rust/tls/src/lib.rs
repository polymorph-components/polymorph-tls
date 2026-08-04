//! The profile's curated TLS 1.3 delivery for Rust guests.
//!
//! This crate turns the policy in [`lann_tls_profile`] into working rustls
//! machinery, all of it pure RustCrypto and wasm-safe per the profile's
//! timing classification:
//!
//! - [`provider()`]: a [`CryptoProvider`] carrying exactly the profile's
//!   cipher suites and key-exchange groups, whose key loader accepts only
//!   Ed25519 private keys.
//! - [`client_config`] / [`server_config`]: TLS 1.3-only rustls configs
//!   under that provider, for WebPKI-style deployments (root-store trust,
//!   X.509 server identity, unauthenticated clients).
//! - [`rpk`]: raw-public-key connections (RFC 7250) — the mutually
//!   authenticated peer-to-peer posture, where a bare Ed25519 key is the
//!   peer's identity.
//!
//! A consumer of this crate makes no algorithm choices. The crate's
//! opinions bind only its users: dropping to rustls directly is always
//! possible, and out of scope here. The one rule this crate can make
//! unrepresentable is the signing rule — no constructor accepts ECDSA or
//! RSA private key material; see [`lann_tls_profile::ServerIdentity`].
//!
//! QUIC integration (quinn compatibility) deliberately lives elsewhere:
//! this crate is TLS only.

use std::fmt;
use std::sync::Arc;

pub mod rpk;

use lann_tls_profile::ServerIdentity;
use rustls::crypto::{CryptoProvider, KeyProvider};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls_pki_types::PrivateKeyDer;

/// The profile's `CryptoProvider`.
///
/// Cipher suites and key-exchange groups are exactly
/// [`lann_tls_profile::CIPHER_SUITES`] and
/// [`lann_tls_profile::KEY_EXCHANGE_GROUPS`], in profile preference order.
/// Signature verification carries rustls-rustcrypto's full (secret-free)
/// algorithm set. The key loader accepts only Ed25519 keys: loading ECDSA
/// or RSA private key material fails rather than producing an in-guest
/// class-D signer.
pub fn provider() -> Arc<CryptoProvider> {
    let base = rustls_rustcrypto::provider();
    let cipher_suites = lann_tls_profile::CIPHER_SUITES
        .iter()
        .map(|id| {
            *base
                .cipher_suites
                .iter()
                .find(|suite| suite.suite() == *id)
                .expect("rustls-rustcrypto provides every profile cipher suite")
        })
        .collect();
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
        cipher_suites,
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

/// A TLS 1.3-only client config under the profile provider.
///
/// Clients under this constructor send no client certificates and hold no
/// identity key: this client path is entirely class ≤ B. For mutually
/// authenticated raw-public-key connections, see [`rpk::client_config`].
pub fn client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// A TLS 1.3-only server config under the profile provider.
///
/// The identity carries the signing policy: an Ed25519 key signing
/// in-guest, or a delegated external signer. See
/// [`lann_tls_profile::ServerIdentity`].
pub fn server_config(identity: ServerIdentity) -> Result<rustls::ServerConfig, rustls::Error> {
    let builder = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the profile provider supports TLS 1.3")
        .with_no_client_auth();
    Ok(match identity {
        ServerIdentity::Ed25519(identity) => {
            let (chain, key) = identity.into_parts();
            builder.with_single_cert(chain, key)?
        }
        ServerIdentity::External { chain, signer } => builder.with_cert_resolver(Arc::new(
            StaticResolver(Arc::new(CertifiedKey::new(chain, signer))),
        )),
    })
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

    /// Guards provider/profile agreement: the assembled provider must offer
    /// exactly the profile's suites and groups, in profile order.
    #[test]
    fn provider_matches_profile() {
        let provider = provider();
        let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(suites, lann_tls_profile::CIPHER_SUITES);
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, lann_tls_profile::KEY_EXCHANGE_GROUPS);
    }

    /// Guards the class-D key rejection: the provider's key loader must
    /// refuse ECDSA private key material.
    #[test]
    fn key_provider_rejects_ecdsa() {
        let p256 = include_bytes!("../../profile/src/testdata/p256-key.p8");
        let key = PrivateKeyDer::Pkcs8(p256.to_vec().into());
        assert!(provider().key_provider.load_private_key(key).is_err());
    }

    /// The key loader accepts the profile's Ed25519 key material.
    #[test]
    fn key_provider_accepts_ed25519() {
        let ed = include_bytes!("../../profile/src/testdata/ed25519-key.p8");
        let key = PrivateKeyDer::Pkcs8(ed.to_vec().into());
        assert!(provider().key_provider.load_private_key(key).is_ok());
    }
}
