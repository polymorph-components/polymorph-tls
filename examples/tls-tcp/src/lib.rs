//! Real-transport demo for the `lann:tls` component: TLS over actual
//! `wasi:sockets` TCP (`wasi:sockets@0.3`).
//!
//! Where `tls-loopback` wires the component's streams to itself in
//! memory, this app hands them to a real transport: the connection's
//! ciphertext output stream *is* the socket's transmit stream, and the
//! socket's receive stream *is* the connection's ciphertext input. The
//! socket layer and the TLS layer each report how their direction ended,
//! so the app can show the distinction the interface is built around:
//! a transport-level close (FIN, or a reset) says nothing about whether
//! the TLS stream ended cleanly — only `close_notify` does.
//!
//! Modes (run composed, under a runtime with component-model async, p3
//! sockets, and network access):
//!
//! ```text
//! tls-tcp client <ip> <port> <server-name> <ca-der> <payload> <expect>
//! tls-tcp server <ip> <port> <leaf-der> <key-p8>
//! ```
//!
//! The protocol is one LF-terminated request line and one LF-terminated
//! response line; the client closes its write direction first, the
//! server responds to the client's `close_notify` in kind. `<expect>`
//! names the close class the client demands of the peer: `clean`
//! (response, then TLS `close_notify`), `truncated` (response, then
//! transport close without `close_notify`), or `reset` (connection
//! reset; the response may be lost). The exit status reports whether
//! the observed class matched.

use wit_bindgen::StreamResult;

wit_bindgen::generate!({
    path: "../../wit",
    inline: "
        package inline:app;
        world app {
            import lann:tls/types@0.1.0;
            import lann:tls/client@0.1.0;
            import lann:tls/server@0.1.0;
        }
    ",
    generate_all,
});

use lann::tls::client::Connector;
use lann::tls::server::{Acceptor, Identity};
use lann::tls::types::Error as TlsError;
use wasip3::sockets::types::{
    ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket,
};

const ALPN: &[u8] = b"tls-interop/1";
/// Stream-read hop size.
const CHUNK: usize = 16 * 1024;

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        let args: Vec<String> = std::env::args().collect();
        let result = match args.get(1).map(String::as_str) {
            Some("client") if args.len() == 8 || args.len() == 9 => {
                let expected_response = args.get(8).unwrap_or(&args[6]).clone();
                client(
                    &args[2],
                    &args[3],
                    &args[4],
                    &args[5],
                    &args[6],
                    &args[7],
                    &expected_response,
                )
                .await
            }
            Some("server") if args.len() == 6 => {
                server(&args[2], &args[3], &args[4], &args[5]).await
            }
            _ => Err(format!(
                "usage: {0} client <ip> <port> <server-name> <ca-der> <payload> \
                 <clean|truncated|reset> [expected-response]\n       \
                 {0} server <ip> <port> <leaf-der> <key-p8>",
                args.first().map(String::as_str).unwrap_or("tls-tcp"),
            )),
        };
        result.map_err(|message| eprintln!("tls-tcp: {message}"))
    }
}

wasip3::cli::command::export!(Component);

/// How a peer ended the connection, as seen through both layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseClass {
    /// TLS `close_notify`: an authenticated end of data.
    Clean,
    /// Transport closed (FIN) without `close_notify`.
    Truncated,
    /// Transport reported an abnormal close (e.g. RST).
    Reset,
}

impl CloseClass {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "clean" => Ok(Self::Clean),
            "truncated" => Ok(Self::Truncated),
            "reset" => Ok(Self::Reset),
            other => Err(format!("unknown close class {other:?}")),
        }
    }
}

async fn client(
    ip: &str,
    port: &str,
    server_name: &str,
    ca_path: &str,
    payload: &str,
    expect: &str,
    expected_response: &str,
) -> Result<(), String> {
    let expect = CloseClass::parse(expect)?;
    let ca = std::fs::read(ca_path).map_err(|e| format!("read {ca_path}: {e}"))?;
    let remote = socket_address(ip, port)?;

    let socket = TcpSocket::create(family(&remote)).map_err(|e| format!("create socket: {e:?}"))?;
    socket
        .connect(remote)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;

    let connector = Connector::new(&[ca]);

    // Wire the transform pair straight into the socket: no copies in this
    // app on the ciphertext side.
    let (mut app_tx, app_rx) = wit_stream::new();
    let (ciphertext_out, send_done) = connector.send(app_rx);
    let transport_tx_done = socket.send(ciphertext_out);
    let (transport_rx, transport_rx_done) = socket.receive();
    let (mut app_rx, recv_done) = connector.receive(transport_rx);

    let info = connector
        .connect(server_name.to_string(), vec![ALPN.to_vec()])
        .await
        .map_err(|e| format!("handshake: {}", e.to_debug_string()))?;
    println!(
        "handshake complete (ALPN {})",
        render_alpn(info.alpn_protocol.as_deref()),
    );

    // One request line; keep the write direction open until the response
    // has arrived so the peer chooses how the connection ends.
    let leftover = app_tx.write_all(format!("{payload}\n").into_bytes()).await;
    assert!(leftover.is_empty(), "cleartext stream rejected the request");

    let (line, mut closed) = read_line(&mut app_rx).await;
    match &line {
        Some(line) => println!("response: {line}"),
        None => println!("no response line (stream closed early)"),
    }

    // Our side closes first: close_notify, then FIN once the TLS stream
    // drains. Keep reading so the peer's close reaches the TLS layer.
    drop(app_tx);
    if !closed {
        closed = drain(&mut app_rx).await;
    }
    debug_assert!(closed);

    let tls_recv = report_tls("tls receive", recv_done.await);
    let _ = report_tls("tls send", send_done.await);
    let transport_recv = report_transport("transport receive", transport_rx_done.await);
    let _ = report_transport("transport send", transport_tx_done.await);

    let observed = match (&tls_recv, &transport_recv) {
        (Ok(()), _) => CloseClass::Clean,
        (Err(_), Err(_)) => CloseClass::Reset,
        (Err(_), Ok(())) => CloseClass::Truncated,
    };
    println!("close class: {observed:?}");

    if observed != expect {
        return Err(format!(
            "expected close class {expect:?}, observed {observed:?}"
        ));
    }
    if observed != CloseClass::Reset && line.as_deref() != Some(expected_response) {
        return Err(format!(
            "response {line:?} does not match expected {expected_response:?}"
        ));
    }
    Ok(())
}

async fn server(ip: &str, port: &str, leaf_path: &str, key_path: &str) -> Result<(), String> {
    let leaf = std::fs::read(leaf_path).map_err(|e| format!("read {leaf_path}: {e}"))?;
    let key = std::fs::read(key_path).map_err(|e| format!("read {key_path}: {e}"))?;
    let local = socket_address(ip, port)?;

    let listener =
        TcpSocket::create(family(&local)).map_err(|e| format!("create socket: {e:?}"))?;
    listener.bind(local).map_err(|e| format!("bind: {e:?}"))?;
    let mut accepts = listener.listen().map_err(|e| format!("listen: {e:?}"))?;
    let bound = listener
        .get_local_address()
        .map_err(|e| format!("local address: {e:?}"))?;
    println!("listening on port {}", port_of(&bound));

    let socket = accepts.next().await.ok_or("listener closed")?;

    let identity = Identity::ed25519(&[leaf], &key)
        .map_err(|e| format!("identity: {}", e.to_debug_string()))?;
    let acceptor = Acceptor::new(&identity);

    let (mut app_tx, app_rx) = wit_stream::new();
    let (ciphertext_out, send_done) = acceptor.send(app_rx);
    let transport_tx_done = socket.send(ciphertext_out);
    let (transport_rx, transport_rx_done) = socket.receive();
    let (mut app_rx, recv_done) = acceptor.receive(transport_rx);

    let info = acceptor
        .accept(vec![ALPN.to_vec()])
        .await
        .map_err(|e| format!("handshake: {}", e.to_debug_string()))?;
    println!(
        "handshake complete (ALPN {}, SNI {})",
        render_alpn(info.alpn_protocol.as_deref()),
        info.server_name.as_deref().unwrap_or("<none>"),
    );

    let (line, closed) = read_line(&mut app_rx).await;
    let line = line.ok_or("connection closed before a request line arrived")?;
    println!("request: {line}");

    let leftover = app_tx.write_all(format!("{line}\n").into_bytes()).await;
    assert!(leftover.is_empty(), "cleartext stream rejected the echo");

    // The client closes first; answer its close_notify with ours.
    if !closed {
        drain(&mut app_rx).await;
    }
    drop(app_tx);

    let tls_recv = report_tls("tls receive", recv_done.await);
    let _ = report_tls("tls send", send_done.await);
    let _ = report_transport("transport receive", transport_rx_done.await);
    let _ = report_transport("transport send", transport_tx_done.await);

    tls_recv.map_err(|_| "client did not close cleanly".to_string())
}

/// Reads cleartext up to the first LF. Returns the line (without the LF)
/// and whether the stream closed while reading.
async fn read_line(stream: &mut wit_bindgen::StreamReader<u8>) -> (Option<String>, bool) {
    let mut data = Vec::new();
    loop {
        if let Some(at) = data.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&data[..at]).into_owned();
            return (Some(line), false);
        }
        let (status, chunk) = stream.read(Vec::with_capacity(CHUNK)).await;
        data.extend_from_slice(&chunk);
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            let line = (!data.is_empty()).then(|| String::from_utf8_lossy(&data).into_owned());
            return (line, true);
        }
    }
}

/// Reads the stream to its end, discarding data. Returns `true`.
async fn drain(stream: &mut wit_bindgen::StreamReader<u8>) -> bool {
    loop {
        let (status, _) = stream.read(Vec::with_capacity(CHUNK)).await;
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            return true;
        }
    }
}

fn report_tls(direction: &str, result: Result<(), TlsError>) -> Result<(), String> {
    match result {
        Ok(()) => {
            println!("{direction}: clean close_notify");
            Ok(())
        }
        Err(e) => {
            let message = e.to_debug_string();
            println!("{direction} error: {message}");
            Err(message)
        }
    }
}

fn report_transport(direction: &str, result: Result<(), ErrorCode>) -> Result<(), ErrorCode> {
    match result {
        Ok(()) => println!("{direction}: closed (FIN)"),
        Err(ref e) => println!("{direction} error: {e:?}"),
    }
    result
}

fn render_alpn(alpn: Option<&[u8]>) -> String {
    alpn.map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "<none>".to_string())
}

fn socket_address(ip: &str, port: &str) -> Result<IpSocketAddress, String> {
    let port: u16 = port.parse().map_err(|e| format!("port {port:?}: {e}"))?;
    let ip: std::net::IpAddr = ip.parse().map_err(|e| format!("ip {ip:?}: {e}"))?;
    Ok(match ip {
        std::net::IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port,
                address: (a, b, c, d),
            })
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port,
                flow_info: 0,
                scope_id: 0,
                address: (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
            })
        }
    })
}

fn family(addr: &IpSocketAddress) -> IpAddressFamily {
    match addr {
        IpSocketAddress::Ipv4(_) => IpAddressFamily::Ipv4,
        IpSocketAddress::Ipv6(_) => IpAddressFamily::Ipv6,
    }
}

fn port_of(addr: &IpSocketAddress) -> u16 {
    match addr {
        IpSocketAddress::Ipv4(a) => a.port,
        IpSocketAddress::Ipv6(a) => a.port,
    }
}
