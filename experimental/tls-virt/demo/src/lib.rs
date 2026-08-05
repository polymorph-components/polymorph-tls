//! Demo app for the `tls-virt` virtualizer: plain TCP, no TLS anywhere
//! in this code.
//!
//! The app resolves a hostname, connects, sends one LF-terminated line,
//! closes its write direction, reads the response until the peer closes,
//! and checks the response is the line reversed (the shape of `openssl
//! s_server -rev`). Run against a name under the virtualizer's
//! `.tls-virt.alt` suffix, all of that happens through a TLS tunnel the
//! app never sees; the printed remote address is the virtualizer's handle
//! address, not the real peer.
//!
//! ```text
//! tls-virt-demo <hostname> <port> <payload>
//! ```

use wasip3::sockets::ip_name_lookup;
use wasip3::sockets::types::{
    IpAddress, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket,
};
use wasip3::wit_bindgen::StreamResult;

/// Stream-read hop size.
const CHUNK: usize = 16 * 1024;

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        let args: Vec<String> = std::env::args().collect();
        let result = match args.as_slice() {
            [_, name, port, payload] => demo(name, port, payload).await,
            _ => Err(format!(
                "usage: {} <hostname> <port> <payload>",
                args.first().map(String::as_str).unwrap_or("tls-virt-demo"),
            )),
        };
        result.map_err(|message| eprintln!("tls-virt-demo: {message}"))
    }
}

wasip3::cli::command::export!(Component);

async fn demo(name: &str, port: &str, payload: &str) -> Result<(), String> {
    let port: u16 = port.parse().map_err(|e| format!("port {port:?}: {e}"))?;

    let addrs = ip_name_lookup::resolve_addresses(name.to_string())
        .await
        .map_err(|e| format!("resolve {name:?}: {e:?}"))?;
    let addr = *addrs.first().ok_or("resolver returned no addresses")?;
    println!("resolved {name} -> {}", render_addr(&addr));

    let remote = socket_address(addr, port);
    let socket = TcpSocket::create(family(&remote)).map_err(|e| format!("create socket: {e:?}"))?;
    socket
        .connect(remote)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    match socket.get_remote_address() {
        Ok(peer) => println!("connected to {}", render_sockaddr(&peer)),
        Err(e) => println!("connected (remote address unavailable: {e:?})"),
    }

    let (mut tx, tx_reader) = wasip3::wit_stream::new();
    let send_done = socket.send(tx_reader);
    let (mut rx, recv_done) = socket.receive();

    let leftover = tx.write_all(format!("{payload}\n").into_bytes()).await;
    assert!(leftover.is_empty(), "transmit stream rejected the request");
    // Close the write direction; the peer answers and then closes.
    drop(tx);

    let mut response = Vec::new();
    loop {
        let (status, chunk) = rx.read(Vec::with_capacity(CHUNK)).await;
        response.extend_from_slice(&chunk);
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            break;
        }
    }
    recv_done
        .await
        .map_err(|e| format!("receive direction: {e:?}"))?;
    send_done
        .await
        .map_err(|e| format!("send direction: {e:?}"))?;

    let response = String::from_utf8_lossy(&response);
    let response = response.trim_end_matches(['\r', '\n']);
    println!("response: {response}");

    let expected: String = payload.chars().rev().collect();
    if response != expected {
        return Err(format!(
            "response {response:?} does not match expected {expected:?}"
        ));
    }
    println!("reversed echo verified; both directions closed cleanly");
    Ok(())
}

fn socket_address(addr: IpAddress, port: u16) -> IpSocketAddress {
    match addr {
        IpAddress::Ipv4(address) => IpSocketAddress::Ipv4(Ipv4SocketAddress { port, address }),
        IpAddress::Ipv6(address) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
            port,
            flow_info: 0,
            address,
            scope_id: 0,
        }),
    }
}

fn family(addr: &IpSocketAddress) -> IpAddressFamily {
    match addr {
        IpSocketAddress::Ipv4(_) => IpAddressFamily::Ipv4,
        IpSocketAddress::Ipv6(_) => IpAddressFamily::Ipv6,
    }
}

fn render_addr(addr: &IpAddress) -> String {
    match *addr {
        IpAddress::Ipv4((a, b, c, d)) => std::net::Ipv4Addr::new(a, b, c, d).to_string(),
        IpAddress::Ipv6(s) => {
            std::net::Ipv6Addr::new(s.0, s.1, s.2, s.3, s.4, s.5, s.6, s.7).to_string()
        }
    }
}

fn render_sockaddr(addr: &IpSocketAddress) -> String {
    match addr {
        IpSocketAddress::Ipv4(v4) => {
            format!("{}:{}", render_addr(&IpAddress::Ipv4(v4.address)), v4.port)
        }
        IpSocketAddress::Ipv6(v6) => format!(
            "[{}]:{}",
            render_addr(&IpAddress::Ipv6(v6.address)),
            v6.port
        ),
    }
}
