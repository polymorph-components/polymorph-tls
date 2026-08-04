//! QUIC over `wasi:sockets` UDP: the profile's TLS 1.3 under quinn-proto.
//!
//! With no arguments, runs the loopback smoke test: a client and server
//! in one guest, each on its own UDP socket, exchanging a stream and
//! then timing out idle.
//!
//! With a mode argument, runs one interop endpoint over real UDP for the
//! cross-implementation rig (one LF-free payload echoed over one
//! bidirectional stream, FIN to FIN):
//!
//! ```text
//! quic-loopback client <ip> <port> <server-name> <ca-der> <payload>
//! quic-loopback server <ip> <port> <leaf-der> <key-p8>
//! ```
//!
//! Exit status is the verdict; run under a WASI runtime with network
//! access (e.g. `wasmtime run -S inherit-network`).

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
fn main() {
    run::main();
}

#[cfg(not(all(target_family = "wasm", target_os = "wasi")))]
fn main() {
    eprintln!("quic-loopback targets wasm32-wasip2; build with --target wasm32-wasip2");
    std::process::exit(2);
}

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod run {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use lann_quinn_wasi::{Driver, UdpSocket};
    use lann_tls_profile::{Ed25519Identity, ServerIdentity};
    use quinn_proto::{
        ClientConfig, ConnectionError, ConnectionHandle, Dir, Endpoint, EndpointConfig, Event,
        ServerConfig, StreamId, TransportConfig, VarInt,
    };
    use rustls_pki_types::CertificateDer;
    use wasi::clocks::monotonic_clock;
    use wasi::io::poll::{self, Pollable};

    const CA_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/ca.der");
    const LEAF_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf.der");
    const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf-key.p8");

    const ALPN: &[&[u8]] = &[b"quic-loopback/1"];
    const INTEROP_ALPN: &[&[u8]] = &[b"quic-interop/1"];
    const MESSAGE: &[u8] = b"hello over the profile's TLS 1.3, via wasi:sockets";
    const IDLE_TIMEOUT_MS: u32 = 300;
    const INTEROP_IDLE_TIMEOUT_MS: u32 = 5_000;

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            None => loopback(),
            Some("client") if args.len() == 7 => {
                client(&args[2], &args[3], &args[4], &args[5], &args[6])
            }
            Some("server") if args.len() == 6 => server(&args[2], &args[3], &args[4], &args[5]),
            _ => {
                eprintln!(
                    "usage: {0}\n       {0} client <ip> <port> <server-name> <ca-der> <payload>\
                     \n       {0} server <ip> <port> <leaf-der> <key-p8>",
                    args.first().map(String::as_str).unwrap_or("quic-loopback"),
                );
                std::process::exit(2);
            }
        }
    }

    fn transport(idle_timeout_ms: u32) -> Arc<TransportConfig> {
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(VarInt::from_u32(idle_timeout_ms).into()));
        Arc::new(transport)
    }

    fn parse_addr(ip: &str, port: &str) -> SocketAddr {
        let ip: IpAddr = ip
            .parse()
            .unwrap_or_else(|e| die(format!("ip {ip:?}: {e}")));
        let port: u16 = port
            .parse()
            .unwrap_or_else(|e| die(format!("port {port:?}: {e}")));
        SocketAddr::new(ip, port)
    }

    fn wildcard(addr: SocketAddr) -> SocketAddr {
        let ip: IpAddr = match addr {
            SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        SocketAddr::new(ip, 0)
    }

    fn die(message: String) -> ! {
        eprintln!("quic-loopback: {message}");
        std::process::exit(1);
    }

    /// Interop client: echo one payload over one bidirectional stream.
    fn client(ip: &str, port: &str, server_name: &str, ca_path: &str, payload: &str) {
        let remote = parse_addr(ip, port);
        let ca = std::fs::read(ca_path).unwrap_or_else(|e| die(format!("read {ca_path}: {e}")));

        let endpoint_config = Arc::new(EndpointConfig::new(Arc::new(
            lann_tls_quinn::ResetKey::new(b"interop reset key (client)"),
        )));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca))
            .unwrap_or_else(|e| die(format!("CA certificate: {e}")));
        let quic_client: lann_tls_quinn::QuicClientConfig =
            lann_tls_quinn::client_config(roots, INTEROP_ALPN)
                .try_into()
                .expect("initial suite");
        let mut config = ClientConfig::new(Arc::new(quic_client));
        config.transport_config(transport(INTEROP_IDLE_TIMEOUT_MS));

        let mut driver = Driver::new(
            Endpoint::new(endpoint_config, None, true, None),
            UdpSocket::bind(wildcard(remote)).expect("bind client socket"),
        );
        let handle = driver
            .connect(config, remote, server_name)
            .expect("connect");

        drive_one(&mut driver, |d| {
            while let Some((_, event)) = d.poll_event() {
                if matches!(event, Event::Connected) {
                    return Some(());
                }
            }
            None
        });
        println!("handshake complete");

        // Send the payload as a finished stream.
        let stream_id = {
            let conn = driver.connection_mut(handle).expect("connection");
            let id = conn.streams().open(Dir::Bi).expect("open stream");
            let mut stream = conn.send_stream(id);
            stream.write(payload.as_bytes()).expect("write");
            stream.finish().expect("finish");
            id
        };

        // Read the echo to FIN.
        let mut response = Vec::new();
        drive_one(&mut driver, |d| {
            while d.poll_event().is_some() {}
            let conn = d.connection_mut(handle)?;
            read_stream(conn, stream_id, &mut response).then_some(())
        });
        println!("response: {}", String::from_utf8_lossy(&response));
        if response != payload.as_bytes() {
            die(format!(
                "response {:?} does not echo request {payload:?}",
                String::from_utf8_lossy(&response),
            ));
        }

        // Close and flush the CONNECTION_CLOSE toward the peer.
        if let Some(conn) = driver.connection_mut(handle) {
            conn.close(Instant::now(), VarInt::from_u32(0), b"done"[..].into());
        }
        drive_one(&mut driver, |d| (!d.has_outbound()).then_some(()));
        println!("connection closed");
        println!("quic interop client OK");
    }

    /// Interop server: accept one connection, echo one stream.
    fn server(ip: &str, port: &str, leaf_path: &str, key_path: &str) {
        let local = parse_addr(ip, port);
        let leaf =
            std::fs::read(leaf_path).unwrap_or_else(|e| die(format!("read {leaf_path}: {e}")));
        let key = std::fs::read(key_path).unwrap_or_else(|e| die(format!("read {key_path}: {e}")));

        let endpoint_config = Arc::new(EndpointConfig::new(Arc::new(
            lann_tls_quinn::ResetKey::new(b"interop reset key (server)"),
        )));
        let identity = Ed25519Identity::from_pkcs8_der(vec![CertificateDer::from(leaf)], &key)
            .unwrap_or_else(|e| die(format!("identity: {e}")));
        let tls_server =
            lann_tls_quinn::server_config(ServerIdentity::Ed25519(identity), INTEROP_ALPN)
                .unwrap_or_else(|e| die(format!("server config: {e}")));
        let quic_server: lann_tls_quinn::QuicServerConfig =
            tls_server.try_into().expect("initial suite");
        let mut server_config = ServerConfig::new(
            Arc::new(quic_server),
            Arc::new(lann_tls_quinn::TokenKey::new(b"interop token key")),
        );
        server_config.transport = transport(INTEROP_IDLE_TIMEOUT_MS);

        let mut driver = Driver::new(
            Endpoint::new(endpoint_config, Some(Arc::new(server_config)), true, None),
            UdpSocket::bind(local).expect("bind server socket"),
        );
        println!("listening on port {}", driver.local_addr().port());

        let handle = drive_one(&mut driver, |d| {
            while let Some((handle, event)) = d.poll_event() {
                if matches!(event, Event::Connected) {
                    return Some(handle);
                }
            }
            None
        });
        println!("connection accepted");

        // Echo one bidirectional stream, FIN to FIN.
        let mut request = Vec::new();
        let mut accepted = None;
        drive_one(&mut driver, |d| {
            while d.poll_event().is_some() {}
            let conn = d.connection_mut(handle)?;
            if accepted.is_none() {
                accepted = conn.streams().accept(Dir::Bi);
            }
            let id = accepted?;
            read_stream(conn, id, &mut request).then_some(())
        });
        println!("request: {}", String::from_utf8_lossy(&request));
        {
            let conn = driver.connection_mut(handle).expect("connection");
            let id = accepted.expect("accepted stream");
            let mut stream = conn.send_stream(id);
            stream.write(&request).expect("write");
            stream.finish().expect("finish");
        }

        // The client closes the connection once it has the echo.
        drive_one(&mut driver, |d| {
            while let Some((_, event)) = d.poll_event() {
                if let Event::ConnectionLost { reason } = event {
                    return match reason {
                        ConnectionError::ApplicationClosed(_) => Some(()),
                        other => die(format!("connection lost: {other}")),
                    };
                }
            }
            None
        });
        println!("connection closed by client");
        println!("quic interop server OK");
    }

    /// Reads all currently available data from `id`; returns `true` once
    /// the stream is finished.
    fn read_stream(conn: &mut quinn_proto::Connection, id: StreamId, into: &mut Vec<u8>) -> bool {
        let mut recv = conn.recv_stream(id);
        let mut fin = false;
        if let Ok(mut chunks) = recv.read(true) {
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(chunk)) => into.extend_from_slice(&chunk.bytes),
                    Ok(None) => {
                        fin = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            let _ = chunks.finalize();
        }
        fin
    }

    fn wait_one(driver: &mut Driver) {
        let mut pollables: Vec<Pollable> = vec![driver.incoming_pollable()];
        if driver.has_outbound() {
            pollables.push(driver.outgoing_pollable());
        }
        if let Some(deadline) = driver.next_deadline() {
            let wait = deadline.saturating_duration_since(Instant::now());
            pollables.push(monotonic_clock::subscribe_duration(wait.as_nanos() as u64));
        }
        let refs: Vec<&Pollable> = pollables.iter().collect();
        poll::poll(&refs);
    }

    /// Pumps one driver until `predicate` yields, with a wall-clock stall
    /// guard.
    fn drive_one<T>(driver: &mut Driver, mut predicate: impl FnMut(&mut Driver) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            while driver.pump().expect("pump") {}
            if let Some(value) = predicate(driver) {
                return value;
            }
            assert!(Instant::now() < deadline, "interop endpoint stalled");
            wait_one(driver);
        }
    }

    fn wait_both(a: &mut Driver, b: &mut Driver) {
        let mut pollables: Vec<Pollable> = vec![a.incoming_pollable(), b.incoming_pollable()];
        if a.has_outbound() {
            pollables.push(a.outgoing_pollable());
        }
        if b.has_outbound() {
            pollables.push(b.outgoing_pollable());
        }
        let now = Instant::now();
        if let Some(deadline) = [a.next_deadline(), b.next_deadline()]
            .into_iter()
            .flatten()
            .min()
        {
            let wait = deadline.saturating_duration_since(now);
            pollables.push(monotonic_clock::subscribe_duration(wait.as_nanos() as u64));
        }
        let refs: Vec<&Pollable> = pollables.iter().collect();
        poll::poll(&refs);
    }

    /// Pumps both drivers until `predicate` yields, with a wall-clock stall
    /// guard.
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
                moved |= client.pump().expect("client pump");
                moved |= server.pump().expect("server pump");
            }
            if let Some(value) = predicate(client, server) {
                return value;
            }
            assert!(Instant::now() < deadline, "smoke test stalled");
            wait_both(client, server);
        }
    }

    pub fn loopback() {
        let local = |port| SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);

        // Server.
        let endpoint_config = Arc::new(EndpointConfig::new(Arc::new(
            lann_tls_quinn::ResetKey::new(b"loopback reset key"),
        )));
        let identity = Ed25519Identity::from_pkcs8_der(
            vec![CertificateDer::from(LEAF_DER.to_vec())],
            LEAF_KEY_P8,
        )
        .expect("leaf key is Ed25519");
        let tls_server = lann_tls_quinn::server_config(ServerIdentity::Ed25519(identity), ALPN)
            .expect("server config");
        let quic_server: lann_tls_quinn::QuicServerConfig =
            tls_server.try_into().expect("initial suite");
        let mut server_config = ServerConfig::new(
            Arc::new(quic_server),
            Arc::new(lann_tls_quinn::TokenKey::new(b"loopback token key")),
        );
        server_config.transport = transport(IDLE_TIMEOUT_MS);
        let mut server = Driver::new(
            Endpoint::new(
                endpoint_config.clone(),
                Some(Arc::new(server_config)),
                true,
                None,
            ),
            UdpSocket::bind(local(0)).expect("bind server socket"),
        );

        // Client.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(CA_DER.to_vec()))
            .expect("CA parses");
        let quic_client: lann_tls_quinn::QuicClientConfig =
            lann_tls_quinn::client_config(roots, ALPN)
                .try_into()
                .expect("initial suite");
        let mut client_config = ClientConfig::new(Arc::new(quic_client));
        client_config.transport_config(transport(IDLE_TIMEOUT_MS));
        let mut client = Driver::new(
            Endpoint::new(endpoint_config, None, true, None),
            UdpSocket::bind(local(0)).expect("bind client socket"),
        );

        let server_addr = server.local_addr();
        let client_handle = client
            .connect(client_config, server_addr, "localhost")
            .expect("connect");

        // Handshake.
        let mut client_connected = false;
        let mut server_handle: Option<ConnectionHandle> = None;
        drive(&mut client, &mut server, |c, s| {
            while let Some((handle, event)) = c.poll_event() {
                assert_eq!(handle, client_handle);
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
        println!(
            "handshake complete (Ed25519 identity, ALPN {})",
            String::from_utf8_lossy(ALPN[0]),
        );

        // Client sends a finished stream.
        {
            let conn = client.connection_mut(client_handle).expect("client conn");
            let id = conn.streams().open(Dir::Bi).expect("open stream");
            let mut stream = conn.send_stream(id);
            stream.write(MESSAGE).expect("write");
            stream.finish().expect("finish");
        }

        // Server reads it to FIN.
        let mut received = Vec::new();
        let mut accepted = None;
        drive(&mut client, &mut server, |_, s| {
            while s.poll_event().is_some() {}
            let conn = s.connection_mut(server_handle).expect("server conn");
            if accepted.is_none() {
                accepted = conn.streams().accept(Dir::Bi);
            }
            let id = accepted?;
            read_stream(conn, id, &mut received).then_some(())
        });
        assert_eq!(received, MESSAGE, "stream payload mismatch");
        println!("stream delivered ({} bytes)", received.len());

        // Idle timeout tears both connections down.
        let mut client_lost = false;
        let mut server_lost = false;
        drive(&mut client, &mut server, |c, s| {
            while let Some((_, event)) = c.poll_event() {
                if let Event::ConnectionLost {
                    reason: ConnectionError::TimedOut,
                } = event
                {
                    client_lost = true;
                }
            }
            while let Some((_, event)) = s.poll_event() {
                if let Event::ConnectionLost {
                    reason: ConnectionError::TimedOut,
                } = event
                {
                    server_lost = true;
                }
            }
            (client_lost && server_lost).then_some(())
        });
        println!("idle timeout observed on both sides");

        println!("loopback OK");
    }
}
