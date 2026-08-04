//! Loopback smoke test: a QUIC client and server in one guest, each on its
//! own `wasi:sockets` UDP socket, exchanging a stream over the profile's
//! TLS 1.3 and then timing out idle.
//!
//! Exit status is the verdict; run under a WASI runtime with network
//! access (e.g. `wasmtime run -S inherit-network`).

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
fn main() {
    run::run();
}

#[cfg(not(all(target_family = "wasm", target_os = "wasi")))]
fn main() {
    eprintln!("quic-loopback targets wasm32-wasip2; build with --target wasm32-wasip2");
    std::process::exit(2);
}

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod run {
    use std::net::{Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use lann_quinn_wasi::{Driver, UdpSocket};
    use lann_tls_profile::{Ed25519Identity, ServerIdentity};
    use quinn_proto::{
        ClientConfig, ConnectionError, ConnectionHandle, Dir, Endpoint, EndpointConfig, Event,
        ServerConfig, TransportConfig, VarInt,
    };
    use rustls_pki_types::CertificateDer;
    use wasi::clocks::monotonic_clock;
    use wasi::io::poll::{self, Pollable};

    const CA_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/ca.der");
    const LEAF_DER: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf.der");
    const LEAF_KEY_P8: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/leaf-key.p8");

    const ALPN: &[&[u8]] = &[b"quic-loopback/1"];
    const MESSAGE: &[u8] = b"hello over the profile's TLS 1.3, via wasi:sockets";
    const IDLE_TIMEOUT_MS: u32 = 300;

    fn transport() -> Arc<TransportConfig> {
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()));
        Arc::new(transport)
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

    pub fn run() {
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
        server_config.transport = transport();
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
        client_config.transport_config(transport());
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
            while let Some(_) = s.poll_event() {}
            let conn = s.connection_mut(server_handle).expect("server conn");
            if accepted.is_none() {
                accepted = conn.streams().accept(Dir::Bi);
            }
            let id = accepted?;
            let mut recv = conn.recv_stream(id);
            let mut fin = false;
            if let Ok(mut chunks) = recv.read(true) {
                loop {
                    match chunks.next(usize::MAX) {
                        Ok(Some(chunk)) => received.extend_from_slice(&chunk.bytes),
                        Ok(None) => {
                            fin = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let _ = chunks.finalize();
            }
            fin.then_some(())
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
