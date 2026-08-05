//! Native mirror of `quic-loopback bench`: the same quinn-proto
//! endpoints, the same profile TLS, the same one-process loopback
//! topology and transfer loop — over `std::net` UDP instead of
//! `wasi:sockets`. The delta between this binary's row and the wasm
//! row isolates the environment (native codegen and syscalls vs
//! Wasmtime and `wasi:sockets`), not the implementation.
//!
//! ```text
//! quic-native-bench <mib>
//! ```
//!
//! Output row: `bench,quic-bulk,native,MB/s,<median>,<min>,<max>`.
//!
//! Waiting is a busy yield rather than a poll on the socket: during a
//! bulk transfer progress is continuous, and a fixed-duration park
//! would wall-clock the loop and understate throughput. The cost is a
//! saturated core, which a bench accepts.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lann_tls_profile::{Ed25519Identity, ServerIdentity};
use quinn_proto::{
    ClientConfig, ConnectionEvent, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    Event, ServerConfig, StreamId, TransportConfig, VarInt,
};
use rustls_pki_types::CertificateDer;

const CA_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/ca.der");
const LEAF_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf.der");
const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf-key.p8");

const ALPN: &[&[u8]] = &[b"quic-bench/1"];
const BATCHES: usize = 3;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mib: usize = match args.get(1).map(|s| s.parse()) {
        Some(Ok(mib)) => mib,
        _ => {
            eprintln!(
                "usage: {} <mib>",
                args.first()
                    .map(String::as_str)
                    .unwrap_or("quic-native-bench"),
            );
            std::process::exit(2);
        }
    };
    bench(mib);
}

fn die(message: String) -> ! {
    eprintln!("quic-native-bench: {message}");
    std::process::exit(1);
}

/// The `std::net` counterpart of `lann_quinn_wasi::Driver`, pump logic
/// mirrored step for step.
struct Driver {
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, quinn_proto::Connection>,
    socket: UdpSocket,
    outbound: VecDeque<(Vec<u8>, SocketAddr)>,
    events: VecDeque<(ConnectionHandle, Event)>,
}

impl Driver {
    fn new(endpoint: Endpoint, socket: UdpSocket) -> Self {
        socket.set_nonblocking(true).expect("nonblocking");
        Self {
            endpoint,
            connections: HashMap::new(),
            socket,
            outbound: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("local addr")
    }

    fn connect(
        &mut self,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> ConnectionHandle {
        let (handle, connection) = self
            .endpoint
            .connect(Instant::now(), config, remote, server_name)
            .expect("connect");
        self.connections.insert(handle, connection);
        handle
    }

    fn connection_mut(&mut self, handle: ConnectionHandle) -> &mut quinn_proto::Connection {
        self.connections.get_mut(&handle).expect("connection")
    }

    fn poll_event(&mut self) -> Option<(ConnectionHandle, Event)> {
        self.events.pop_front()
    }

    fn deliver(&mut self, handle: ConnectionHandle, event: ConnectionEvent) {
        if let Some(connection) = self.connections.get_mut(&handle) {
            connection.handle_event(event);
        }
    }

    fn pump(&mut self) -> bool {
        let mut moved = false;
        let now = Instant::now();
        let mut buf = Vec::new();
        let mut datagram = [0u8; 65536];

        loop {
            match self.socket.recv_from(&mut datagram) {
                Ok((len, remote)) => {
                    moved = true;
                    buf.clear();
                    match self.endpoint.handle(
                        now,
                        remote,
                        None,
                        None,
                        bytes::BytesMut::from(&datagram[..len]),
                        &mut buf,
                    ) {
                        Some(DatagramEvent::NewConnection(incoming)) => {
                            buf.clear();
                            match self.endpoint.accept(incoming, now, &mut buf, None) {
                                Ok((handle, connection)) => {
                                    self.connections.insert(handle, connection);
                                }
                                Err(err) => {
                                    if let Some(transmit) = err.response {
                                        self.outbound.push_back((
                                            buf[..transmit.size].to_vec(),
                                            transmit.destination,
                                        ));
                                    }
                                }
                            }
                        }
                        Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                            self.deliver(handle, event);
                        }
                        Some(DatagramEvent::Response(transmit)) => {
                            self.outbound
                                .push_back((buf[..transmit.size].to_vec(), transmit.destination));
                        }
                        None => {}
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => die(format!("recv_from: {e}")),
            }
        }

        let mut endpoint_events = Vec::new();
        for (handle, connection) in self.connections.iter_mut() {
            if let Some(deadline) = connection.poll_timeout() {
                if deadline <= now {
                    connection.handle_timeout(now);
                    moved = true;
                }
            }
            while let Some(event) = connection.poll_endpoint_events() {
                endpoint_events.push((*handle, event));
            }
            loop {
                buf.clear();
                match connection.poll_transmit(now, 1, &mut buf) {
                    Some(transmit) => {
                        moved = true;
                        self.outbound
                            .push_back((buf[..transmit.size].to_vec(), transmit.destination));
                    }
                    None => break,
                }
            }
            while let Some(event) = connection.poll() {
                moved = true;
                self.events.push_back((*handle, event));
            }
        }
        for (handle, event) in endpoint_events {
            let drained = event.is_drained();
            if let Some(reply) = self.endpoint.handle_event(handle, event) {
                self.deliver(handle, reply);
                moved = true;
            }
            if drained {
                self.connections.remove(&handle);
                moved = true;
            }
        }

        while let Some((data, remote)) = self.outbound.front() {
            match self.socket.send_to(data, remote) {
                Ok(_) => {
                    moved = true;
                    self.outbound.pop_front();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => die(format!("send_to: {e}")),
            }
        }

        moved
    }
}

/// Pumps both drivers until `predicate` yields; parks briefly when
/// nothing moves.
fn drive<T>(
    client: &mut Driver,
    server: &mut Driver,
    mut predicate: impl FnMut(&mut Driver, &mut Driver) -> Option<T>,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut moved = true;
        while moved {
            moved = false;
            moved |= client.pump();
            moved |= server.pump();
        }
        if let Some(value) = predicate(client, server) {
            return value;
        }
        assert!(Instant::now() < deadline, "bench stalled");
        std::thread::yield_now();
    }
}

fn drain_stream(conn: &mut quinn_proto::Connection, id: StreamId) -> (usize, bool) {
    let mut recv = conn.recv_stream(id);
    let mut n = 0;
    let mut fin = false;
    if let Ok(mut chunks) = recv.read(false) {
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => n += chunk.bytes.len(),
                Ok(None) => {
                    fin = true;
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = chunks.finalize();
    }
    (n, fin)
}

fn bench(mib: usize) {
    let bytes = mib * 1024 * 1024;

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
    let transport = Arc::new(transport);

    let local = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0);
    let endpoint_config = Arc::new(EndpointConfig::new(Arc::new(
        lann_tls_quinn::ResetKey::new(b"bench reset key"),
    )));
    let identity =
        Ed25519Identity::from_pkcs8_der(vec![CertificateDer::from(LEAF_DER.to_vec())], LEAF_KEY_P8)
            .expect("leaf key is Ed25519");
    let tls_server = lann_tls_quinn::server_config(ServerIdentity::Ed25519(identity), ALPN)
        .expect("server config");
    let quic_server: lann_tls_quinn::QuicServerConfig =
        tls_server.try_into().expect("initial suite");
    let mut server_config = ServerConfig::new(
        Arc::new(quic_server),
        Arc::new(lann_tls_quinn::TokenKey::new(b"bench token key")),
    );
    server_config.transport = transport.clone();
    let mut server = Driver::new(
        Endpoint::new(
            endpoint_config.clone(),
            Some(Arc::new(server_config)),
            true,
            None,
        ),
        UdpSocket::bind(local).expect("bind server socket"),
    );

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_DER.to_vec()))
        .expect("CA parses");
    let quic_client: lann_tls_quinn::QuicClientConfig = lann_tls_quinn::client_config(roots, ALPN)
        .try_into()
        .expect("initial suite");
    let mut client_config = ClientConfig::new(Arc::new(quic_client));
    client_config.transport_config(transport);
    let mut client = Driver::new(
        Endpoint::new(endpoint_config, None, true, None),
        UdpSocket::bind(local).expect("bind client socket"),
    );

    let server_addr = server.local_addr();
    let client_handle = client.connect(client_config, server_addr, "localhost");

    let mut client_connected = false;
    let mut server_handle: Option<ConnectionHandle> = None;
    drive(&mut client, &mut server, |c, s| {
        while let Some((_, event)) = c.poll_event() {
            if matches!(event, Event::Connected) {
                client_connected = true;
            }
        }
        while let Some((handle, event)) = s.poll_event() {
            if matches!(event, Event::Connected) {
                server_handle = Some(handle);
            }
        }
        (client_connected && server_handle.is_some()).then_some(())
    });
    let server_handle = server_handle.unwrap();

    let mut transfer = |bytes: usize| -> f64 {
        let chunk = vec![0xa5u8; 64 * 1024];
        let id = {
            let conn = client.connection_mut(client_handle);
            conn.streams().open(Dir::Bi).expect("open stream")
        };
        let mut written = 0usize;
        let mut finished = false;
        let mut received = 0usize;
        let mut fin_seen = false;
        let mut accepted: Option<StreamId> = None;
        let start = Instant::now();
        drive(&mut client, &mut server, |c, s| {
            while let Some((_, event)) = c.poll_event() {
                if let Event::ConnectionLost { reason } = event {
                    die(format!("client connection lost: {reason}"));
                }
            }
            while let Some((_, event)) = s.poll_event() {
                if let Event::ConnectionLost { reason } = event {
                    die(format!("server connection lost: {reason}"));
                }
            }

            if written < bytes || !finished {
                let conn = c.connection_mut(client_handle);
                let mut stream = conn.send_stream(id);
                while written < bytes {
                    let want = (bytes - written).min(chunk.len());
                    match stream.write(&chunk[..want]) {
                        Ok(0) => break,
                        Ok(n) => written += n,
                        Err(quinn_proto::WriteError::Blocked) => break,
                        Err(e) => die(format!("stream write: {e}")),
                    }
                }
                if written >= bytes && !finished {
                    stream.finish().expect("finish");
                    finished = true;
                }
                while c.pump() {}
            }

            let conn = s.connection_mut(server_handle);
            if accepted.is_none() {
                accepted = conn.streams().accept(Dir::Bi);
            }
            if let Some(id) = accepted {
                let (n, fin) = drain_stream(conn, id);
                if n > 0 {
                    received += n;
                    while s.pump() {}
                }
                fin_seen |= fin;
            }
            (fin_seen && received >= bytes).then_some(())
        });
        bytes as f64 / start.elapsed().as_secs_f64() / 1e6
    };

    transfer((bytes / 4).max(1024 * 1024));
    let mut rates: Vec<f64> = (0..BATCHES).map(|_| transfer(bytes)).collect();
    rates.sort_by(|a, b| a.total_cmp(b));
    println!(
        "bench,quic-bulk,native,MB/s,{:.1},{:.1},{:.1}",
        rates[rates.len() / 2],
        rates[0],
        rates[rates.len() - 1],
    );
}
