//! End-to-end validation: a quinn-proto handshake and stream exchange over
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
use lann_tls_profile::{Ed25519Identity, ServerIdentity};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    Event, ServerConfig,
};
use rustls_pki_types::CertificateDer;

const CA_DER: &[u8] = include_bytes!("testdata/ca.der");
const LEAF_DER: &[u8] = include_bytes!("testdata/leaf.der");
const LEAF_KEY_P8: &[u8] = include_bytes!("testdata/leaf-key.p8");

const ALPN: &[&[u8]] = &[b"lann-tls-test/1"];

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
    fn new() -> Self {
        let endpoint_config = Arc::new(EndpointConfig::new(Arc::new(
            lann_tls_quinn::ResetKey::new(b"test reset key"),
        )));

        let identity = Ed25519Identity::from_pkcs8_der(
            vec![CertificateDer::from(LEAF_DER.to_vec())],
            LEAF_KEY_P8,
        )
        .expect("testdata leaf key is Ed25519");
        let tls_server = lann_tls_quinn::server_config(ServerIdentity::Ed25519(identity), ALPN)
            .expect("server config builds");
        let quic_server: lann_tls_quinn::QuicServerConfig =
            tls_server.try_into().expect("initial suite present");
        let server_config = ServerConfig::new(
            Arc::new(quic_server),
            Arc::new(lann_tls_quinn::TokenKey::new(b"test token master")),
        );

        let client = Endpoint::new(endpoint_config.clone(), None, true, None);
        let server = Endpoint::new(endpoint_config, Some(Arc::new(server_config)), true, None);

        Self {
            client,
            server,
            client_conn: None,
            server_conn: None,
            now: Instant::now(),
        }
    }

    fn connect(&mut self) {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(CA_DER.to_vec()))
            .expect("testdata CA parses");
        let tls_client = lann_tls_quinn::client_config(roots, ALPN);
        let quic_client: lann_tls_quinn::QuicClientConfig =
            tls_client.try_into().expect("initial suite present");
        let config = ClientConfig::new(Arc::new(quic_client));
        let (ch, conn) = self
            .client
            .connect(self.now, config, server_addr(), "localhost")
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
                match conn.poll_transmit(now, 1, &mut buf) {
                    Some(_) => outbound.push(BytesMut::from(&buf[..])),
                    None => break,
                }
            }
        }

        // Deliver them to the receiving side.
        for datagram in outbound {
            moved = true;
            buf.clear();
            match to.handle(now, from_addr, None, None, datagram, &mut buf) {
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

#[test]
fn handshake_and_stream_roundtrip() {
    let mut pump = Pump::new();
    pump.connect();

    // Handshake to Connected on both sides.
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

    // The server saw the client's SNI.
    {
        let (_, conn) = pump.server_conn.as_mut().unwrap();
        let data = conn
            .crypto_session()
            .handshake_data()
            .expect("handshake data after Connected");
        let data = data
            .downcast_ref::<lann_tls_quinn::HandshakeData>()
            .expect("handshake data type");
        assert_eq!(data.server_name.as_deref(), Some("localhost"));
        assert_eq!(data.protocol.as_deref(), Some(&b"lann-tls-test/1"[..]));
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
