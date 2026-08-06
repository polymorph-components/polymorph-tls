//! End-to-end validation: a noq-proto handshake and stream exchange over
//! the profile's TLS stack, pumped in memory (no sockets).
//!
//! This exercises the whole assembly at once: initial keys, header and
//! packet protection for both suites' machinery, the TLS 1.3 handshake
//! through rustls with the pure-RustCrypto provider, and an Ed25519
//! CertificateVerify signed in-guest-style via the profile's identity
//! path.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use noq_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    Event, FourTuple, ServerConfig,
};
use polymorph_tls_profile::{Ed25519Identity, RpkIdentity, ServerIdentity};
use rustls_pki_types::CertificateDer;

const CA_DER: &[u8] = include_bytes!("testdata/ca.der");
const LEAF_DER: &[u8] = include_bytes!("testdata/leaf.der");
const LEAF_KEY_P8: &[u8] = include_bytes!("testdata/leaf-key.p8");

const ALPN: &[&[u8]] = &[b"polymorph-tls-test/1"];

fn client_addr() -> SocketAddr {
    SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433)
}

fn server_addr() -> SocketAddr {
    SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4434)
}

struct Pump {
    client: Endpoint,
    server: Endpoint,
    client_conn: Option<(ConnectionHandle, Connection)>,
    server_conn: Option<(ConnectionHandle, Connection)>,
    now: Instant,
}

impl Pump {
    fn new(tls_server: rustls::ServerConfig) -> Self {
        let endpoint_config = Arc::new(EndpointConfig::new(Arc::new(
            polymorph_tls_quic::ResetKey::new(b"test reset key"),
        )));

        let quic_server: polymorph_tls_quic::QuicServerConfig =
            tls_server.try_into().expect("initial suite present");
        let server_config = ServerConfig::new(
            Arc::new(quic_server),
            Arc::new(polymorph_tls_quic::TokenKey::new(b"test token master")),
        );

        let client = Endpoint::new(endpoint_config.clone(), None, true);
        let server = Endpoint::new(endpoint_config, Some(Arc::new(server_config)), true);

        Self {
            client,
            server,
            client_conn: None,
            server_conn: None,
            now: Instant::now(),
        }
    }

    fn connect(&mut self, tls_client: rustls::ClientConfig, server_name: &str) {
        let quic_client: polymorph_tls_quic::QuicClientConfig =
            tls_client.try_into().expect("initial suite present");
        let config = ClientConfig::new(Arc::new(quic_client));
        let (ch, conn) = self
            .client
            .connect(self.now, config, server_addr(), server_name)
            .expect("connect");
        self.client_conn = Some((ch, conn));
    }

    /// One round of: drain transmits from one side, feed them to the other.
    /// Returns whether anything moved.
    fn pump_once(&mut self) -> bool {
        let mut moved = false;
        moved |= Self::flush_side(
            &mut self.client,
            &mut self.client_conn,
            &mut self.server,
            &mut self.server_conn,
            client_addr(),
            self.now,
        );
        moved |= Self::flush_side(
            &mut self.server,
            &mut self.server_conn,
            &mut self.client,
            &mut self.client_conn,
            server_addr(),
            self.now,
        );
        moved
    }

    fn flush_side(
        from: &mut Endpoint,
        from_conn: &mut Option<(ConnectionHandle, Connection)>,
        to: &mut Endpoint,
        to_conn: &mut Option<(ConnectionHandle, Connection)>,
        from_addr: SocketAddr,
        now: Instant,
    ) -> bool {
        let mut moved = false;
        let mut buf = Vec::with_capacity(0x10000);

        // Collect datagrams from the sending side's connection.
        let mut outbound = Vec::new();
        if let Some((_, conn)) = from_conn.as_mut() {
            loop {
                buf.clear();
                match conn.poll_transmit(now, std::num::NonZeroUsize::MIN, &mut buf) {
                    Some(_) => outbound.push(BytesMut::from(&buf[..])),
                    None => break,
                }
            }
        }

        // Deliver them to the receiving side.
        for datagram in outbound {
            moved = true;
            buf.clear();
            match to.handle(
                now,
                FourTuple::new(from_addr, None),
                None,
                datagram,
                &mut buf,
            ) {
                Some(DatagramEvent::NewConnection(incoming)) => {
                    buf.clear();
                    let (ch, conn) = to
                        .accept(incoming, now, &mut buf, None)
                        .expect("accept incoming connection");
                    *to_conn = Some((ch, conn));
                }
                Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                    let (conn_ch, conn) = to_conn.as_mut().expect("event for known connection");
                    assert_eq!(*conn_ch, ch);
                    conn.handle_event(event);
                }
                Some(DatagramEvent::Response { .. }) => {
                    panic!("unexpected endpoint-level response in loopback test");
                }
                None => {}
            }
        }

        // Shuttle endpoint events (CID issuance and friends) both ways.
        if let Some((ch, conn)) = from_conn.as_mut() {
            while let Some(event) = conn.poll_endpoint_events() {
                if let Some(reply) = from.handle_event(*ch, event) {
                    conn.handle_event(reply);
                    moved = true;
                }
            }
        }
        if let Some((ch, conn)) = to_conn.as_mut() {
            while let Some(event) = conn.poll_endpoint_events() {
                if let Some(reply) = to.handle_event(*ch, event) {
                    conn.handle_event(reply);
                    moved = true;
                }
            }
        }

        moved
    }

    fn advance_time(&mut self) {
        let deadlines: Vec<_> = [&mut self.client_conn, &mut self.server_conn]
            .into_iter()
            .flatten()
            .filter_map(|(_, conn)| conn.poll_timeout())
            .collect();
        if let Some(next) = deadlines.into_iter().min() {
            if next > self.now {
                self.now = next;
            }
            for (_, conn) in [&mut self.client_conn, &mut self.server_conn]
                .into_iter()
                .flatten()
            {
                conn.handle_timeout(self.now);
            }
        } else {
            self.now += Duration::from_millis(10);
        }
    }

    /// Pumps until both sides report `predicate`, panicking on stall.
    fn run_until(&mut self, mut predicate: impl FnMut(&mut Self) -> bool) {
        for _ in 0..1000 {
            if predicate(self) {
                return;
            }
            if !self.pump_once() {
                self.advance_time();
            }
        }
        panic!("test stalled before reaching the expected state");
    }
}

fn drain_events(conn: &mut Connection) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = conn.poll() {
        events.push(event);
    }
    events
}

/// Runs both sides to `Connected`, or panics on stall.
fn handshake_to_connected(pump: &mut Pump) {
    let mut client_connected = false;
    let mut server_connected = false;
    pump.run_until(|p| {
        if let Some((_, conn)) = p.client_conn.as_mut() {
            for event in drain_events(conn) {
                if matches!(event, Event::Connected) {
                    client_connected = true;
                }
            }
        }
        if let Some((_, conn)) = p.server_conn.as_mut() {
            for event in drain_events(conn) {
                if matches!(event, Event::Connected) {
                    server_connected = true;
                }
            }
        }
        client_connected && server_connected
    });
}

fn webpki_server_config() -> rustls::ServerConfig {
    let identity =
        Ed25519Identity::from_pkcs8_der(vec![CertificateDer::from(LEAF_DER.to_vec())], LEAF_KEY_P8)
            .expect("testdata leaf key is Ed25519");
    polymorph_tls_quic::server_config(ServerIdentity::Ed25519(identity), ALPN)
        .expect("server config builds")
}

fn webpki_client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_DER.to_vec()))
        .expect("testdata CA parses");
    polymorph_tls_quic::client_config(roots, ALPN)
}

#[test]
fn handshake_and_stream_roundtrip() {
    let mut pump = Pump::new(webpki_server_config());
    pump.connect(webpki_client_config(), "localhost");

    handshake_to_connected(&mut pump);

    // The server saw the client's SNI.
    {
        let (_, conn) = pump.server_conn.as_mut().unwrap();
        let data = conn
            .crypto_session()
            .handshake_data()
            .expect("handshake data after Connected");
        let data = data
            .downcast_ref::<polymorph_tls_quic::HandshakeData>()
            .expect("handshake data type");
        assert_eq!(data.server_name.as_deref(), Some("localhost"));
        assert_eq!(data.protocol.as_deref(), Some(&b"polymorph-tls-test/1"[..]));
    }

    // Client opens a bidirectional stream and sends a message.
    const MESSAGE: &[u8] = b"hello over the profile's TLS 1.3";
    let stream_id = {
        let (_, conn) = pump.client_conn.as_mut().unwrap();
        let id = conn.streams().open(Dir::Bi).expect("stream available");
        let mut stream = conn.send_stream(id);
        stream.write(MESSAGE).expect("write");
        stream.finish().expect("finish");
        id
    };

    // Server receives it all.
    let mut received = Vec::new();
    let mut fin = false;
    let mut accepted = None;
    pump.run_until(|p| {
        let (_, conn) = p.server_conn.as_mut().unwrap();
        for _ in drain_events(conn) {}
        if accepted.is_none() {
            accepted = conn.streams().accept(Dir::Bi);
        }
        let Some(id) = accepted else {
            return false;
        };
        let mut recv = conn.recv_stream(id);
        if let Ok(mut chunks) = recv.read(true) {
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(chunk)) => received.extend_from_slice(&chunk.bytes),
                    // `Ok(None)` is FIN: the peer finished the stream.
                    Ok(None) => {
                        fin = true;
                        break;
                    }
                    Err(_) => break, // blocked: more to come
                }
            }
            let _ = chunks.finalize();
        }
        fin
    });

    assert_eq!(received, MESSAGE);
    let _ = stream_id;
}

const CLIENT_KEY_P8: &[u8] = include_bytes!("testdata/client-key.p8");

/// The peer's authenticated raw public key, read from the connection.
fn rpk_peer_key(conn: &mut Connection) -> [u8; 32] {
    let identity = conn
        .crypto_session()
        .peer_identity()
        .expect("peer identity after Connected");
    let certs = identity
        .downcast_ref::<Vec<CertificateDer<'static>>>()
        .expect("peer identity type");
    assert_eq!(certs.len(), 1, "raw public keys carry exactly one entry");
    polymorph_tls::rpk::peer_public_key(&certs[0]).expect("peer presented an Ed25519 SPKI")
}

/// Mutually authenticated raw-public-key handshake: both sides read the
/// peer's key and it is exactly the other identity's key.
#[test]
fn rpk_mutual_handshake() {
    let server_identity =
        RpkIdentity::from_pkcs8_der(LEAF_KEY_P8).expect("testdata leaf key is Ed25519");
    let client_identity =
        RpkIdentity::from_pkcs8_der(CLIENT_KEY_P8).expect("testdata client key is Ed25519");

    let mut pump = Pump::new(
        polymorph_tls_quic::rpk_server_config(&server_identity, ALPN).expect("server config"),
    );
    pump.connect(
        polymorph_tls_quic::rpk_client_config(
            &client_identity,
            &server_identity.public_key(),
            ALPN,
        )
        .expect("client config"),
        "rpk.invalid",
    );

    handshake_to_connected(&mut pump);

    let (_, conn) = pump.server_conn.as_mut().unwrap();
    assert_eq!(rpk_peer_key(conn), client_identity.public_key());
    let (_, conn) = pump.client_conn.as_mut().unwrap();
    assert_eq!(rpk_peer_key(conn), server_identity.public_key());
}

/// A wrong pin must not produce a connection: the client rejects the
/// server's key during the handshake.
#[test]
fn rpk_wrong_pin_fails() {
    let server_identity =
        RpkIdentity::from_pkcs8_der(LEAF_KEY_P8).expect("testdata leaf key is Ed25519");
    let client_identity =
        RpkIdentity::from_pkcs8_der(CLIENT_KEY_P8).expect("testdata client key is Ed25519");

    let mut wrong_key = server_identity.public_key();
    wrong_key[0] ^= 1;

    let mut pump = Pump::new(
        polymorph_tls_quic::rpk_server_config(&server_identity, ALPN).expect("server config"),
    );
    pump.connect(
        polymorph_tls_quic::rpk_client_config(&client_identity, &wrong_key, ALPN)
            .expect("client config"),
        "rpk.invalid",
    );

    let mut client_failed = false;
    pump.run_until(|p| {
        if let Some((_, conn)) = p.client_conn.as_mut() {
            for event in drain_events(conn) {
                match event {
                    Event::ConnectionLost { .. } => client_failed = true,
                    Event::Connected => panic!("connection must not complete under a wrong pin"),
                    _ => {}
                }
            }
        }
        client_failed
    });
}
