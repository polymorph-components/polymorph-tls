//! Case support: the fixture material and the loopback connection the
//! suite's connection-lifecycle cases share.
//!
//! One suite instance plays both endpoints: a `connector` and an
//! `acceptor` from the composed TLS component, wired to each other by
//! passing each side's ciphertext output stream directly as the other
//! side's transport input — no sockets, no copies in the suite.

use wit_bindgen::{FutureReader, StreamReader, StreamResult, StreamWriter};

use crate::polymorph::tls::client::Connector;
use crate::polymorph::tls::server::{Acceptor, Identity};
use crate::polymorph::tls::types::{ConnectionInfo, Error};
use crate::wit_stream;

pub const CA_DER: &[u8] = include_bytes!("../../../rust/quic/tests/testdata/ca.der");
pub const LEAF_DER: &[u8] = include_bytes!("../../../rust/quic/tests/testdata/leaf.der");
pub const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quic/tests/testdata/leaf-key.p8");
pub const P256_KEY_P8: &[u8] = include_bytes!("../../../rust/profile/src/testdata/p256-key.p8");

pub const ALPN: &[u8] = b"conformance-ct/1";
pub const SERVER_NAME: &str = "localhost";

pub fn render(e: Error) -> String {
    e.to_debug_string()
}

/// The in-guest Ed25519 identity from the fixture chain.
pub fn ed25519_identity() -> Result<Identity, String> {
    Identity::ed25519(&[LEAF_DER.to_vec()], LEAF_KEY_P8).map_err(render)
}

/// A connected TLS loopback: handshake complete on both sides,
/// application-data streams open in both directions.
pub struct Loopback {
    pub client_info: ConnectionInfo,
    pub server_info: ConnectionInfo,
    pub client_tx: StreamWriter<u8>,
    pub client_rx: StreamReader<u8>,
    pub server_tx: StreamWriter<u8>,
    pub server_rx: StreamReader<u8>,
    pub client_send_done: FutureReader<Result<(), Error>>,
    pub client_recv_done: FutureReader<Result<(), Error>>,
    pub server_send_done: FutureReader<Result<(), Error>>,
    pub server_recv_done: FutureReader<Result<(), Error>>,
}

/// Connects a fresh loopback pair as `identity`, offering [`ALPN`] on
/// both sides and [`SERVER_NAME`] as SNI.
pub async fn connect(identity: &Identity) -> Result<Loopback, String> {
    let connector = Connector::new(&[CA_DER.to_vec()]);
    let acceptor = Acceptor::new(identity);

    // Client → server path: the client's ciphertext output stream *is*
    // the server's transport input.
    let (client_tx, client_app_rx) = wit_stream::new();
    let (client_ct, client_send_done) = connector.send(client_app_rx);
    let (server_rx, server_recv_done) = acceptor.receive(client_ct);

    // Server → client path, symmetrically.
    let (server_tx, server_app_rx) = wit_stream::new();
    let (server_ct, server_send_done) = acceptor.send(server_app_rx);
    let (client_rx, client_recv_done) = connector.receive(server_ct);

    // Handshake, both sides concurrently: `accept` spawns the server's
    // pumps, so the two calls must overlap.
    let (client_info, server_info) = futures::join!(
        connector.connect(SERVER_NAME.to_string(), vec![ALPN.to_vec()]),
        acceptor.accept(vec![ALPN.to_vec()]),
    );
    let client_info = client_info.map_err(|e| format!("client handshake: {}", render(e)))?;
    let server_info = server_info.map_err(|e| format!("server handshake: {}", render(e)))?;

    Ok(Loopback {
        client_info,
        server_info,
        client_tx,
        client_rx,
        server_tx,
        server_rx,
        client_send_done,
        client_recv_done,
        server_send_done,
        server_recv_done,
    })
}

impl Loopback {
    /// Closes both write directions and requires every direction future
    /// to resolve cleanly (close_notify, not truncation). The pumps run
    /// detached inside the TLS component, so sequential awaits cannot
    /// deadlock.
    pub async fn shutdown(self) -> Result<(), String> {
        drop(self.client_tx);
        drop(self.server_tx);
        for (name, result) in [
            ("client send", self.client_send_done.await),
            ("server receive", self.server_recv_done.await),
            ("server send", self.server_send_done.await),
            ("client receive", self.client_recv_done.await),
        ] {
            result.map_err(|e| format!("{name} direction: {}", render(e)))?;
        }
        Ok(())
    }
}

/// Reads from `stream` until `len` bytes have arrived (the transforms
/// may deliver data in arbitrary chunks).
pub async fn read_exact(stream: &mut StreamReader<u8>, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        let (status, chunk) = stream.read(Vec::with_capacity(len - data.len())).await;
        data.extend_from_slice(&chunk);
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            break;
        }
    }
    data
}
