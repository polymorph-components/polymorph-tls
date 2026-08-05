//! WASI 0.2 demo app for the tls-virt-wasmtime delivery: plain
//! `std::net`, no TLS anywhere in this code, no wasm-specific code at
//! all.
//!
//! Rust's std on wasm32-wasip2 implements `std::net` over
//! `wasi:sockets@0.2.x`, which is exactly the surface the embedding's
//! 0.2 interposition wraps: the resolver call behind `ToSocketAddrs`
//! returns a minted handle address for a `.tls-virt.alt` name, the
//! `TcpStream` connect and IO tunnel through TLS, `Shutdown::Write`
//! becomes close_notify, and `peer_addr` keeps reporting the handle.
//!
//! Same protocol as the wasip3 demo: send one LF-terminated line, close
//! the write direction, read the response until the peer closes, and
//! check it is the line reversed (the shape of `openssl s_server
//! -rev`).
//!
//! ```text
//! tls-virt-demo-p2 <hostname> <port> <payload>
//! ```

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpStream, ToSocketAddrs as _};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.as_slice() {
        [_, name, port, payload] => demo(name, port, payload),
        _ => Err(format!(
            "usage: {} <hostname> <port> <payload>",
            args.first()
                .map(String::as_str)
                .unwrap_or("tls-virt-demo-p2"),
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tls-virt-demo-p2: {message}");
            ExitCode::FAILURE
        }
    }
}

fn demo(name: &str, port: &str, payload: &str) -> Result<(), String> {
    let port: u16 = port.parse().map_err(|e| format!("port {port:?}: {e}"))?;

    let addrs: Vec<_> = (name, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {name:?}: {e}"))?
        .collect();
    let first = addrs.first().ok_or("resolver returned no addresses")?;
    println!("resolved {name} -> {}", first.ip());

    let mut stream = TcpStream::connect(&addrs[..]).map_err(|e| format!("connect: {e}"))?;
    match stream.peer_addr() {
        Ok(peer) => println!("connected to {peer}"),
        Err(e) => println!("connected (remote address unavailable: {e})"),
    }

    stream
        .write_all(format!("{payload}\n").as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    // Close the write direction; the peer answers and then closes.
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("receive: {e}"))?;

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
