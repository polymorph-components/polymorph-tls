//! `wasi:sockets` virtualizer component: transparent TLS tunneling.
//!
//! The guest delivery of the tls-virt scheme (`tls-virt-common`).
//! Imports and exports the same `wasi:sockets/types` and
//! `wasi:sockets/ip-name-lookup` interfaces — the exports face the
//! composed application, the imports face the host — backed by the
//! host's implementations plus the composed `polymorph:tls` client:
//!
//! - Resolving a name under the `.tls-virt.alt` suffix resolves the real
//!   name via the host, stores the destination in a handle table, and
//!   returns a minted handle address.
//! - Connecting to a handle address opens a real connection to a stored
//!   address and drives a TLS handshake with the stored hostname (SNI +
//!   verification); the application's bytes are then tunneled through
//!   the TLS connection. Ciphertext streams pass to the socket by
//!   handle; the data path adds one small splice task on the transmit
//!   side only.
//! - Everything else — unsuffixed names, addresses outside the handle
//!   prefix, UDP — passes through to the host unchanged, with transport
//!   verdict futures reissued by handle rather than by task.
//!
//! Limits (see README.md): trust roots are baked test fixtures, ALPN is
//! not offered, socket options set before a tunneled connect are not
//! migrated to the real socket, `listen` is not supported, and TLS
//! failures are reported as `connection-reset`/stream closure with
//! detail on stderr.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use futures::channel::oneshot;
use tls_virt_common::{strip_suffix, Entry, HandleTable};
use wit_bindgen::{FutureReader, StreamReader, StreamResult, StreamWriter};

// One `generate!` over the mixed world, with structurally equal types
// merged: the exported copy's types are aliases of the imported
// originals, so one payload vtable per equivalence class serves both
// directions and values cross without conversion (see README.md).
wit_bindgen::generate!({
    path: "wit",
    world: "virtualizer",
    generate_all,
    merge_structurally_equal_types: true,
});

use exports::wasi::sockets::ip_name_lookup::Guest as LookupGuest;
use exports::wasi::sockets::types::{
    Guest as TypesGuest, GuestTcpSocket, GuestUdpSocket, TcpSocket as TcpSocketResource,
    UdpSocket as UdpSocketResource,
};
use polymorph::tls::client::Connector;
use wasi::sockets::ip_name_lookup as host_lookup;
use wasi::sockets::types as host;

/// Trust anchors for tunneled connections (the repository's test CA;
/// see README.md).
const ROOTS: &[&[u8]] = &[include_bytes!("../../quinn/tests/testdata/ca.der")];

/// Stream-read hop size for the transmit splice.
const CHUNK: usize = 16 * 1024;

thread_local! {
    /// The handle-address table (`tls-virt-common`).
    static TABLE: RefCell<HandleTable> = RefCell::new(HandleTable::new());
}

fn mint_handle(entry: Entry) -> host::IpAddress {
    let handle = TABLE.with(|t| t.borrow_mut().mint(entry));
    let s = handle.segments();
    host::IpAddress::Ipv6((s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
}

/// The destination a handle socket-address refers to, if it is one.
fn lookup_handle(remote: &host::IpSocketAddress) -> Option<(String, Vec<IpAddr>, u16)> {
    let host::IpSocketAddress::Ipv6(v6) = remote else {
        return None;
    };
    let (a, b, c, d, e, f, g, h) = v6.address;
    let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
    TABLE.with(|t| {
        t.borrow()
            .lookup(&addr)
            .map(|e| (e.hostname.clone(), e.addrs.clone(), v6.port))
    })
}

struct Component;

export!(Component);

impl TypesGuest for Component {
    type TcpSocket = VTcp;
    type UdpSocket = VUdp;
}

impl LookupGuest for Component {
    async fn resolve_addresses(
        name: String,
    ) -> Result<Vec<host::IpAddress>, host_lookup::ErrorCode> {
        match strip_suffix(&name) {
            Some(real) => {
                let real = real.to_string();
                let addrs = host_lookup::resolve_addresses(real.clone()).await?;
                if addrs.is_empty() {
                    return Err(host_lookup::ErrorCode::NameUnresolvable);
                }
                Ok(vec![mint_handle(Entry {
                    hostname: real,
                    addrs: addrs.into_iter().map(addr_to_std).collect(),
                })])
            }
            None => host_lookup::resolve_addresses(name).await,
        }
    }
}

// --- TCP ---

enum TcpState {
    /// Pass-through: every operation delegates to this host socket.
    Host(host::TcpSocket),
    /// TLS tunnel to a handle address.
    Tunnel(Tunnel),
    /// Transitional state during `connect`.
    Busy,
}

/// A direction verdict in the exported interface's terms.
type VVerdict = FutureReader<Result<(), host::ErrorCode>>;

/// Task-scope note: every long-lived tunnel task (the transmit splice and
/// the verdict mappers) is spawned inside `connect`, the one async-lifted
/// export on this path. wit-bindgen spawns only run within an async
/// export's task scope; a spawn from a sync-lifted export (`send`,
/// `receive`) is queued but never polled. The sync exports therefore only
/// hand out endpoints created at connect time.
struct Tunnel {
    /// The handle address the application dialed, for `get-remote-address`.
    remote: host::IpSocketAddress,
    /// The real connection under the tunnel (also serves option queries).
    host: host::TcpSocket,
    /// Delivers the application's transmit stream to the splice task in
    /// `connect`'s scope; taken by `send`. Dropped unclaimed (socket
    /// dropped without `send`), the pipe closes and the TLS send
    /// direction ends with close_notify.
    app_stream_tx: Option<oneshot::Sender<StreamReader<u8>>>,
    /// Pre-created send verdict; taken by `send`.
    send_verdict: Option<VVerdict>,
    /// Decrypted receive stream and its pre-created verdict; taken by
    /// `receive`.
    cleartext: Option<(StreamReader<u8>, VVerdict)>,
    /// Keeps the transport transmit verdict subscribed.
    _transport_tx_done: FutureReader<Result<(), host::ErrorCode>>,
    /// Keeps the TLS connection resource alive.
    _connector: Connector,
}

pub struct VTcp {
    state: RefCell<TcpState>,
}

impl VTcp {
    fn host_op<T>(&self, op: impl FnOnce(&host::TcpSocket) -> T) -> Result<T, host::ErrorCode> {
        match &*self.state.borrow() {
            TcpState::Host(s) => Ok(op(s)),
            TcpState::Tunnel(t) => Ok(op(&t.host)),
            TcpState::Busy => Err(host::ErrorCode::InvalidState),
        }
    }
}

impl GuestTcpSocket for VTcp {
    fn create(address_family: host::IpAddressFamily) -> Result<TcpSocketResource, host::ErrorCode> {
        let socket = host::TcpSocket::create(address_family)?;
        Ok(TcpSocketResource::new(VTcp {
            state: RefCell::new(TcpState::Host(socket)),
        }))
    }

    fn bind(&self, local_address: host::IpSocketAddress) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.bind(local_address))?
    }

    async fn connect(&self, remote_address: host::IpSocketAddress) -> Result<(), host::ErrorCode> {
        let Some((hostname, addrs, port)) = lookup_handle(&remote_address) else {
            // Pass-through. Take the socket out so the borrow does not
            // span the await.
            let state = std::mem::replace(&mut *self.state.borrow_mut(), TcpState::Busy);
            let TcpState::Host(socket) = state else {
                *self.state.borrow_mut() = state;
                return Err(host::ErrorCode::InvalidState);
            };
            let result = socket.connect(remote_address).await;
            *self.state.borrow_mut() = TcpState::Host(socket);
            return result;
        };

        // Tunnel path: connect the real transport.
        let real_addr =
            tls_virt_common::pick_addr(&addrs, port).ok_or(host::ErrorCode::RemoteUnreachable)?;
        let real = host::TcpSocket::create(match &real_addr {
            SocketAddr::V4(_) => host::IpAddressFamily::Ipv4,
            SocketAddr::V6(_) => host::IpAddressFamily::Ipv6,
        })?;
        real.connect(sockaddr_from_std(real_addr)).await?;

        // Wire the TLS transforms: ciphertext straight onto the socket,
        // application transmit through a pipe (its stream arrives later,
        // at `send`).
        let connector = Connector::new(&ROOTS.iter().map(|r| r.to_vec()).collect::<Vec<_>>());
        let (pipe_writer, pipe_reader) = wit_stream::new();
        let (ciphertext_out, send_done) = connector.send(pipe_reader);
        let transport_tx_done = real.send(ciphertext_out);
        let (ciphertext_in, _transport_rx_done) = real.receive();
        let (cleartext_in, recv_done) = connector.receive(ciphertext_in);

        connector
            .connect(hostname.clone(), vec![])
            .await
            .map_err(|e| {
                eprintln!(
                    "tls-virt: TLS handshake with {hostname:?} failed: {}",
                    e.to_debug_string()
                );
                host::ErrorCode::ConnectionReset
            })?;

        // The long-lived tunnel tasks, spawned here so they live in this
        // async export's task scope (see the note on `Tunnel`). This task
        // stays alive until they finish, which is when both TLS
        // directions have ended.
        let (send_verdict_writer, send_verdict) =
            wit_future::new::<Result<(), host::ErrorCode>>(|| Err(host::ErrorCode::Other(None)));
        let (recv_verdict_writer, recv_verdict) =
            wit_future::new::<Result<(), host::ErrorCode>>(|| Err(host::ErrorCode::Other(None)));
        let (app_stream_tx, app_stream_rx) = oneshot::channel::<StreamReader<u8>>();

        wit_bindgen::spawn_local(async move {
            // The application's transmit stream arrives when it calls
            // `send`; a dropped sender means the socket was dropped
            // without one. Either way the pipe writer drops at the end,
            // which sends TLS close_notify.
            if let Ok(data) = app_stream_rx.await {
                splice(data, pipe_writer).await;
            } else {
                drop(pipe_writer);
            }
            let result = send_done.await.map_err(|e| {
                eprintln!("tls-virt: send direction failed: {}", e.to_debug_string());
                host::ErrorCode::ConnectionReset
            });
            let _ = send_verdict_writer.write(result).await;
        });

        wit_bindgen::spawn_local(async move {
            let result = recv_done.await.map_err(|e| {
                eprintln!(
                    "tls-virt: receive direction failed: {}",
                    e.to_debug_string()
                );
                host::ErrorCode::ConnectionReset
            });
            let _ = recv_verdict_writer.write(result).await;
        });

        *self.state.borrow_mut() = TcpState::Tunnel(Tunnel {
            remote: remote_address,
            host: real,
            app_stream_tx: Some(app_stream_tx),
            send_verdict: Some(send_verdict),
            cleartext: Some((cleartext_in, recv_verdict)),
            _transport_tx_done: transport_tx_done,
            _connector: connector,
        });
        Ok(())
    }

    fn send(&self, data: StreamReader<u8>) -> VVerdict {
        match &mut *self.state.borrow_mut() {
            TcpState::Host(s) => s.send(data),
            TcpState::Tunnel(t) => {
                let (Some(tx), Some(verdict)) = (t.app_stream_tx.take(), t.send_verdict.take())
                else {
                    return invalid_state_verdict();
                };
                let _ = tx.send(data);
                verdict
            }
            TcpState::Busy => invalid_state_verdict(),
        }
    }

    fn receive(&self) -> (StreamReader<u8>, VVerdict) {
        match &mut *self.state.borrow_mut() {
            TcpState::Host(s) => s.receive(),
            TcpState::Tunnel(t) => match t.cleartext.take() {
                Some(pair) => pair,
                None => closed_receive(),
            },
            TcpState::Busy => closed_receive(),
        }
    }

    fn listen(&self) -> Result<StreamReader<TcpSocketResource>, host::ErrorCode> {
        // Wrapping each accepted host socket into an exported resource
        // needs a live task, and this sync-lifted export has no task
        // scope to host one (see the note on `Tunnel` and README.md).
        eprintln!("tls-virt: listen is not supported");
        Err(host::ErrorCode::NotSupported)
    }

    fn get_local_address(&self) -> Result<host::IpSocketAddress, host::ErrorCode> {
        self.host_op(|s| s.get_local_address())?
    }

    fn get_remote_address(&self) -> Result<host::IpSocketAddress, host::ErrorCode> {
        match &*self.state.borrow() {
            // Preserve the illusion: the application dialed the handle.
            TcpState::Tunnel(t) => Ok(t.remote),
            TcpState::Host(s) => s.get_remote_address(),
            TcpState::Busy => Err(host::ErrorCode::InvalidState),
        }
    }

    fn get_is_listening(&self) -> bool {
        self.host_op(|s| s.get_is_listening()).unwrap_or(false)
    }

    fn get_address_family(&self) -> host::IpAddressFamily {
        match &*self.state.borrow() {
            TcpState::Tunnel(_) => host::IpAddressFamily::Ipv6,
            TcpState::Host(s) => s.get_address_family(),
            TcpState::Busy => host::IpAddressFamily::Ipv6,
        }
    }

    fn set_listen_backlog_size(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_listen_backlog_size(value))?
    }

    fn get_keep_alive_enabled(&self) -> Result<bool, host::ErrorCode> {
        self.host_op(|s| s.get_keep_alive_enabled())?
    }

    fn set_keep_alive_enabled(&self, value: bool) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_keep_alive_enabled(value))?
    }

    fn get_keep_alive_idle_time(&self) -> Result<u64, host::ErrorCode> {
        self.host_op(|s| s.get_keep_alive_idle_time())?
    }

    fn set_keep_alive_idle_time(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_keep_alive_idle_time(value))?
    }

    fn get_keep_alive_interval(&self) -> Result<u64, host::ErrorCode> {
        self.host_op(|s| s.get_keep_alive_interval())?
    }

    fn set_keep_alive_interval(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_keep_alive_interval(value))?
    }

    fn get_keep_alive_count(&self) -> Result<u32, host::ErrorCode> {
        self.host_op(|s| s.get_keep_alive_count())?
    }

    fn set_keep_alive_count(&self, value: u32) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_keep_alive_count(value))?
    }

    fn get_hop_limit(&self) -> Result<u8, host::ErrorCode> {
        self.host_op(|s| s.get_hop_limit())?
    }

    fn set_hop_limit(&self, value: u8) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_hop_limit(value))?
    }

    fn get_receive_buffer_size(&self) -> Result<u64, host::ErrorCode> {
        self.host_op(|s| s.get_receive_buffer_size())?
    }

    fn set_receive_buffer_size(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_receive_buffer_size(value))?
    }

    fn get_send_buffer_size(&self) -> Result<u64, host::ErrorCode> {
        self.host_op(|s| s.get_send_buffer_size())?
    }

    fn set_send_buffer_size(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.host_op(|s| s.set_send_buffer_size(value))?
    }
}

/// A verdict already resolved to `err(invalid-state)`: the writer drops
/// unused, so the reader observes the default value.
fn invalid_state_verdict() -> VVerdict {
    let (writer, reader) =
        wit_future::new::<Result<(), host::ErrorCode>>(|| Err(host::ErrorCode::InvalidState));
    drop(writer);
    reader
}

/// A receive pair for sockets with nothing to give: an already-closed
/// stream and an invalid-state verdict.
fn closed_receive() -> (StreamReader<u8>, VVerdict) {
    let (stream_writer, stream_reader) = wit_stream::new::<u8>();
    drop(stream_writer);
    (stream_reader, invalid_state_verdict())
}

/// Pumps the application's transmit stream into the TLS cleartext pipe;
/// dropping the pipe writer on completion signals close (close_notify).
async fn splice(mut from: StreamReader<u8>, mut to: StreamWriter<u8>) {
    loop {
        let (status, buf) = from.read(Vec::with_capacity(CHUNK)).await;
        if !buf.is_empty() {
            let leftover = to.write_all(buf).await;
            if !leftover.is_empty() {
                return;
            }
        }
        if matches!(status, StreamResult::Dropped | StreamResult::Cancelled) {
            return;
        }
    }
}

// --- UDP: pure pass-through ---

pub struct VUdp {
    inner: host::UdpSocket,
}

impl GuestUdpSocket for VUdp {
    fn create(address_family: host::IpAddressFamily) -> Result<UdpSocketResource, host::ErrorCode> {
        let socket = host::UdpSocket::create(address_family)?;
        Ok(UdpSocketResource::new(VUdp { inner: socket }))
    }

    fn bind(&self, local_address: host::IpSocketAddress) -> Result<(), host::ErrorCode> {
        self.inner.bind(local_address)
    }

    fn connect(&self, remote_address: host::IpSocketAddress) -> Result<(), host::ErrorCode> {
        self.inner.connect(remote_address)
    }

    fn disconnect(&self) -> Result<(), host::ErrorCode> {
        self.inner.disconnect()
    }

    async fn send(
        &self,
        data: Vec<u8>,
        remote_address: Option<host::IpSocketAddress>,
    ) -> Result<(), host::ErrorCode> {
        self.inner.send(data, remote_address).await
    }

    async fn receive(&self) -> Result<(Vec<u8>, host::IpSocketAddress), host::ErrorCode> {
        self.inner.receive().await
    }

    fn get_local_address(&self) -> Result<host::IpSocketAddress, host::ErrorCode> {
        self.inner.get_local_address()
    }

    fn get_remote_address(&self) -> Result<host::IpSocketAddress, host::ErrorCode> {
        self.inner.get_remote_address()
    }

    fn get_address_family(&self) -> host::IpAddressFamily {
        self.inner.get_address_family()
    }

    fn get_unicast_hop_limit(&self) -> Result<u8, host::ErrorCode> {
        self.inner.get_unicast_hop_limit()
    }

    fn set_unicast_hop_limit(&self, value: u8) -> Result<(), host::ErrorCode> {
        self.inner.set_unicast_hop_limit(value)
    }

    fn get_receive_buffer_size(&self) -> Result<u64, host::ErrorCode> {
        self.inner.get_receive_buffer_size()
    }

    fn set_receive_buffer_size(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.inner.set_receive_buffer_size(value)
    }

    fn get_send_buffer_size(&self) -> Result<u64, host::ErrorCode> {
        self.inner.get_send_buffer_size()
    }

    fn set_send_buffer_size(&self, value: u64) -> Result<(), host::ErrorCode> {
        self.inner.set_send_buffer_size(value)
    }
}

// --- type mapping between the imported and exported interfaces ---
/// A resolved host-side address in the handle table's terms.
fn addr_to_std(addr: host::IpAddress) -> IpAddr {
    match addr {
        host::IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)),
        host::IpAddress::Ipv6(s) => {
            IpAddr::V6(Ipv6Addr::new(s.0, s.1, s.2, s.3, s.4, s.5, s.6, s.7))
        }
    }
}

/// A picked destination in the host interface's terms.
fn sockaddr_from_std(addr: SocketAddr) -> host::IpSocketAddress {
    match addr {
        SocketAddr::V4(v4) => host::IpSocketAddress::Ipv4(host::Ipv4SocketAddress {
            port: v4.port(),
            address: {
                let [a, b, c, d] = v4.ip().octets();
                (a, b, c, d)
            },
        }),
        SocketAddr::V6(v6) => host::IpSocketAddress::Ipv6(host::Ipv6SocketAddress {
            port: v6.port(),
            flow_info: 0,
            address: {
                let s = v6.ip().segments();
                (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
            },
            scope_id: 0,
        }),
    }
}
