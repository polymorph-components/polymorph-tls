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
    fn delegated(_chain: Vec<Vec<u8>>) -> Result<exports::lann::tls::server::Identity, Error> {
        Err(TlsError::resource(
            "no signer is composed: this build serves the `tls` world; delegated identities \
             require the `tls-delegated` world",
        ))
    }

    #[cfg(feature = "delegated-signer")]
    fn delegated(chain: Vec<Vec<u8>>) -> Result<exports::lann::tls::server::Identity, Error> {
        Ok(exports::lann::tls::server::Identity::new(Self::Delegated {
            chain: chain.into_iter().map(CertificateDer::from).collect(),
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
