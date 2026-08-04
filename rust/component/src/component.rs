//! The `lann:tls` component: the algorithm profile's enforced delivery.
//!
//! Exports the package's `client` and `server` interfaces over
//! component-model async streams, implemented with rustls over the
//! pure-RustCrypto profile provider (`lann-tls`). Consumers get no
//! algorithm-configuration surface; the signing policy is structural
//! (`identity::ed25519` accepts Ed25519 PKCS#8 only, `identity::delegated`
//! holds no key at all).

use std::cell::RefCell;
use std::sync::Arc;

use rustls_pki_types::CertificateDer;
use wit_bindgen::{FutureReader, StreamReader};

#[cfg(not(feature = "delegated-signer"))]
wit_bindgen::generate!({
    path: "../../wit",
    world: "tls",
    generate_all,
});

#[cfg(feature = "delegated-signer")]
wit_bindgen::generate!({
    path: "../../wit",
    world: "tls-delegated",
    generate_all,
    // The signer interface is async-typed (implementations may suspend),
    // but rustls consumes signatures synchronously, so these imports are
    // sync-lowered: the calling task blocks while the signer subtask runs.
    async: [
        "-import:lann:tls/signer@0.1.0#sign",
        "-import:lann:tls/signer@0.1.0#schemes",
    ],
});

use exports::lann::tls::client::{Guest as ClientGuest, GuestConnector};
use exports::lann::tls::server::{Guest as ServerGuest, GuestAcceptor, GuestIdentity};
use exports::lann::tls::types::{ConnectionInfo, Error, Guest as TypesGuest, GuestError};

use crate::pump::Wired;

struct Component;

export!(Component);

impl TypesGuest for Component {
    type Error = TlsError;
}

impl ClientGuest for Component {
    type Connector = Connector;
}

impl ServerGuest for Component {
    type Identity = Identity;
    type Acceptor = Acceptor;
}

/// The `types.error` resource: a rendered diagnostic.
pub struct TlsError(String);

impl TlsError {
    pub(crate) fn resource(message: impl Into<String>) -> Error {
        Error::new(Self(message.into()))
    }
}

impl GuestError for TlsError {
    fn to_debug_string(&self) -> String {
        self.0.clone()
    }
}

/// The `client.connector` resource.
pub struct Connector {
    roots: Vec<CertificateDer<'static>>,
    wired: RefCell<Wired>,
}

impl GuestConnector for Connector {
    fn new(roots: Vec<Vec<u8>>) -> Self {
        Self {
            roots: roots.into_iter().map(CertificateDer::from).collect(),
            wired: RefCell::new(Wired::default()),
        }
    }

    fn send(
        &self,
        cleartext: StreamReader<u8>,
    ) -> (StreamReader<u8>, FutureReader<Result<(), Error>>) {
        self.wired.borrow_mut().wire_send(cleartext)
    }

    fn receive(
        &self,
        ciphertext: StreamReader<u8>,
    ) -> (StreamReader<u8>, FutureReader<Result<(), Error>>) {
        self.wired.borrow_mut().wire_receive(ciphertext)
    }

    async fn connect(
        &self,
        server_name: String,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<ConnectionInfo, Error> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in &self.roots {
            roots
                .add(cert.clone())
                .map_err(|e| TlsError::resource(format!("invalid root certificate: {e}")))?;
        }
        let mut config = lann_tls::client_config(roots);
        config.alpn_protocols = alpn_protocols;

        let name = rustls_pki_types::ServerName::try_from(server_name.clone())
            .map_err(|_| TlsError::resource(format!("invalid server name: {server_name:?}")))?;
        let connection = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|e| TlsError::resource(format!("connection setup failed: {e}")))?;

        let wired =
            self.wired.borrow_mut().take_complete().ok_or_else(|| {
                TlsError::resource("send and receive must be wired before connect")
            })?;
        crate::pump::run(rustls::Connection::Client(connection), wired).await
    }
}

/// The `server.identity` resource.
pub enum Identity {
    Ed25519(lann_tls_profile::Ed25519Identity),
    #[cfg_attr(not(feature = "delegated-signer"), allow(dead_code))]
    Delegated {
        chain: Vec<CertificateDer<'static>>,
        /// The composed signer's schemes, fetched once at construction.
        schemes: Vec<rustls::SignatureScheme>,
    },
}

impl GuestIdentity for Identity {
    fn ed25519(
        chain: Vec<Vec<u8>>,
        private_key_pkcs8_der: Vec<u8>,
    ) -> Result<exports::lann::tls::server::Identity, Error> {
        let chain = chain.into_iter().map(CertificateDer::from).collect();
        let identity =
            lann_tls_profile::Ed25519Identity::from_pkcs8_der(chain, &private_key_pkcs8_der)
                .map_err(|e| TlsError::resource(e.to_string()))?;
        Ok(exports::lann::tls::server::Identity::new(Self::Ed25519(
            identity,
        )))
    }

    #[cfg(not(feature = "delegated-signer"))]
    async fn delegated(
        _chain: Vec<Vec<u8>>,
    ) -> Result<exports::lann::tls::server::Identity, Error> {
        Err(TlsError::resource(
            "no signer is composed: this build serves the `tls` world; delegated identities \
             require the `tls-delegated` world",
        ))
    }

    #[cfg(feature = "delegated-signer")]
    async fn delegated(chain: Vec<Vec<u8>>) -> Result<exports::lann::tls::server::Identity, Error> {
        let schemes = delegated::signer_schemes();
        if schemes.is_empty() {
            return Err(TlsError::resource(
                "the composed signer reports no usable signature schemes",
            ));
        }
        Ok(exports::lann::tls::server::Identity::new(Self::Delegated {
            chain: chain.into_iter().map(CertificateDer::from).collect(),
            schemes,
        }))
    }
}

/// The `server.acceptor` resource.
pub struct Acceptor {
    identity: RefCell<Option<lann_tls_profile::ServerIdentity>>,
    wired: RefCell<Wired>,
}

impl GuestAcceptor for Acceptor {
    fn new(identity: exports::lann::tls::server::IdentityBorrow<'_>) -> Self {
        let identity: &Identity = identity.get();
        let server_identity = match identity {
            Identity::Ed25519(id) => {
                // Rebuild from parts: the identity resource stays usable for
                // further acceptors.
                let (chain, key) = (id.chain().to_vec(), id.key_der());
                lann_tls_profile::Ed25519Identity::from_pkcs8_der(chain, key.secret_der())
                    .map(lann_tls_profile::ServerIdentity::Ed25519)
                    .ok()
            }
            #[cfg(feature = "delegated-signer")]
            Identity::Delegated { chain, schemes } => {
                Some(lann_tls_profile::ServerIdentity::External {
                    chain: chain.clone(),
                    signer: Arc::new(delegated::DelegatedKey::new(schemes.clone())),
                })
            }
            #[cfg(not(feature = "delegated-signer"))]
            Identity::Delegated { .. } => None,
        };
        Self {
            identity: RefCell::new(server_identity),
            wired: RefCell::new(Wired::default()),
        }
    }

    fn send(
        &self,
        cleartext: StreamReader<u8>,
    ) -> (StreamReader<u8>, FutureReader<Result<(), Error>>) {
        self.wired.borrow_mut().wire_send(cleartext)
    }

    fn receive(
        &self,
        ciphertext: StreamReader<u8>,
    ) -> (StreamReader<u8>, FutureReader<Result<(), Error>>) {
        self.wired.borrow_mut().wire_receive(ciphertext)
    }

    async fn accept(&self, alpn_protocols: Vec<Vec<u8>>) -> Result<ConnectionInfo, Error> {
        let identity = self
            .identity
            .borrow_mut()
            .take()
            .ok_or_else(|| TlsError::resource("acceptor has no usable identity"))?;
        let mut config = lann_tls::server_config(identity)
            .map_err(|e| TlsError::resource(format!("server config failed: {e}")))?;
        config.alpn_protocols = alpn_protocols;

        let connection = rustls::ServerConnection::new(Arc::new(config))
            .map_err(|e| TlsError::resource(format!("connection setup failed: {e}")))?;

        let wired =
            self.wired.borrow_mut().take_complete().ok_or_else(|| {
                TlsError::resource("send and receive must be wired before accept")
            })?;
        crate::pump::run(rustls::Connection::Server(connection), wired).await
    }
}

/// Handshake outcome plumbing shared with `pump`.
pub(crate) struct HandshakeOutcome {
    pub alpn_protocol: Option<Vec<u8>>,
    pub server_name: Option<String>,
}

impl From<HandshakeOutcome> for ConnectionInfo {
    fn from(outcome: HandshakeOutcome) -> Self {
        Self {
            alpn_protocol: outcome.alpn_protocol,
            server_name: outcome.server_name,
        }
    }
}

/// The delegated-signing bridge: rustls's synchronous signing seam over
/// the composed signer import.
///
/// The signer interface is async-typed, but these bindings are
/// sync-lowered (see the `generate!` invocation): rustls produces the
/// server flight — CertificateVerify included — inside its synchronous
/// state machine, so the calling task blocks for the duration of the
/// signer subtask. That is legal for async-lifted tasks, which all of
/// this component's callers are.
#[cfg(feature = "delegated-signer")]
mod delegated {
    use rustls::sign::{Signer, SigningKey};
    use rustls::{SignatureAlgorithm, SignatureScheme};

    use super::lann::tls::signer as import;

    fn from_wit(scheme: import::SignatureScheme) -> SignatureScheme {
        match scheme {
            import::SignatureScheme::EcdsaSecp256r1Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
            import::SignatureScheme::EcdsaSecp384r1Sha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            import::SignatureScheme::RsaPssRsaeSha256 => SignatureScheme::RSA_PSS_SHA256,
            import::SignatureScheme::RsaPssRsaeSha384 => SignatureScheme::RSA_PSS_SHA384,
            import::SignatureScheme::RsaPssRsaeSha512 => SignatureScheme::RSA_PSS_SHA512,
            import::SignatureScheme::Ed25519 => SignatureScheme::ED25519,
        }
    }

    fn to_wit(scheme: SignatureScheme) -> import::SignatureScheme {
        match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => import::SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => import::SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::RSA_PSS_SHA256 => import::SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RSA_PSS_SHA384 => import::SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RSA_PSS_SHA512 => import::SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::ED25519 => import::SignatureScheme::Ed25519,
            _ => unreachable!("scheme set originates from from_wit"),
        }
    }

    /// The composed signer's schemes, in its preference order.
    pub(crate) fn signer_schemes() -> Vec<SignatureScheme> {
        import::schemes().into_iter().map(from_wit).collect()
    }

    /// A rustls `SigningKey` whose signatures come from the composed
    /// signer.
    #[derive(Debug)]
    pub(crate) struct DelegatedKey {
        schemes: Vec<SignatureScheme>,
    }

    impl DelegatedKey {
        pub(crate) fn new(schemes: Vec<SignatureScheme>) -> Self {
            Self { schemes }
        }
    }

    impl SigningKey for DelegatedKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            let scheme = self
                .schemes
                .iter()
                .copied()
                .find(|scheme| offered.contains(scheme))?;
            Some(Box::new(DelegatedSigner { scheme }))
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            match self.schemes.first() {
                Some(SignatureScheme::ED25519) => SignatureAlgorithm::ED25519,
                Some(
                    SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::ECDSA_NISTP384_SHA384,
                ) => SignatureAlgorithm::ECDSA,
                Some(
                    SignatureScheme::RSA_PSS_SHA256
                    | SignatureScheme::RSA_PSS_SHA384
                    | SignatureScheme::RSA_PSS_SHA512,
                ) => SignatureAlgorithm::RSA,
                _ => SignatureAlgorithm::Unknown(0),
            }
        }
    }

    #[derive(Debug)]
    struct DelegatedSigner {
        scheme: SignatureScheme,
    }

    impl Signer for DelegatedSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            import::sign(to_wit(self.scheme), message)
                .map_err(|e| rustls::Error::General(format!("delegated signer failed: {e}")))
        }

        fn scheme(&self) -> SignatureScheme {
            self.scheme
        }
    }
}
