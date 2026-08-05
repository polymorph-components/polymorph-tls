//! Experimental `wasi:sockets` virtualizer: transparent TLS tunneling.
//!
//! Exports a structural copy of `wasi:sockets/types` and
//! `wasi:sockets/ip-name-lookup` (under the `virt:sockets` package name;
//! see world.wit), backed by the host's implementations of the same
//! interfaces plus the composed `lann:tls` client:
//!
//! - Resolving a name under the `.tls-virt.alt` suffix resolves the real
//!   name via the host, stores `(hostname, addresses)` in a table, and
//!   returns a **handle address**: a random 64-bit suffix under a random
//!   ULA /64 prefix (RFC 4193 `fd00::/8`) chosen at startup. Handle
//!   addresses never appear on the wire.
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
//! Prototype limits (see README.md): trust roots are baked test
//! fixtures, ALPN is not offered, socket options set before a tunneled
//! connect are not migrated to the real socket, `listen` is not
//! supported, and TLS failures are reported as `connection-reset`/stream
//! closure with detail on stderr.

use std::cell::RefCell;
use std::collections::HashMap;

use futures::channel::oneshot;
use wit_bindgen::{FutureReader, StreamReader, StreamResult, StreamWriter};

/// The host-facing bindings (imports only). Generated separately from the
/// exports: one mixed world trips wit-bindgen 0.60's structural
/// deduplication of future/stream payload vtables, which folds the
/// export-side `future<result<_, error-code>>` payload onto the
/// import-side one and leaves the export-side Rust type without a
/// `FuturePayload` impl (see README.md). Two invocations of the same
/// wit-bindgen crate share one runtime, so values flow between them.
mod host_bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "virtualizer-imports",
        generate_all,
    });
}

/// The application-facing bindings (exports only).
mod virt_bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "virtualizer-exports",
        generate_all,
    });
}

use host_bindings::lann::tls::client::Connector;
use host_bindings::wasi::sockets::ip_name_lookup as host_lookup;
use host_bindings::wasi::sockets::types as host;
use virt_bindings::exports::virt::sockets::ip_name_lookup::{
    ErrorCode as VLookupErrorCode, Guest as LookupGuest,
};
use virt_bindings::exports::virt::sockets::types::{
    ErrorCode as VErrorCode, Guest as TypesGuest, GuestTcpSocket, GuestUdpSocket,
    IpAddress as VIpAddress, IpAddressFamily as VFamily, IpSocketAddress as VIpSocketAddress,
    Ipv4SocketAddress as VIpv4SocketAddress, Ipv6SocketAddress as VIpv6SocketAddress,
    TcpSocket as VTcpSocketResource, UdpSocket as VUdpSocketResource,
};

/// Names under this suffix opt in to TLS tunneling.
const SUFFIX: &str = ".tls-virt.alt";

/// Trust anchors for tunneled connections (prototype: the repository's
/// test CA).
const ROOTS: &[&[u8]] = &[include_bytes!(
    "../../../../rust/quinn/tests/testdata/ca.der"
)];

/// Stream-read hop size for the transmit splice.
const CHUNK: usize = 16 * 1024;

struct Entry {
    hostname: String,
    addrs: Vec<host::IpAddress>,
}

thread_local! {
    /// Handle table: random 64-bit suffix → resolved destination.
    static TABLE: RefCell<HashMap<u64, Entry>> = RefCell::new(HashMap::new());
    /// The random ULA /64 this instance mints handles under.
    static PREFIX: [u8; 8] = {
        let mut prefix = [0u8; 8];
        getrandom::fill(&mut prefix).expect("randomness available");
        prefix[0] = 0xfd;
        prefix
    };
}

fn mint_handle(entry: Entry) -> VIpAddress {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).expect("randomness available");
    let key = u64::from_be_bytes(suffix);
    TABLE.with(|t| t.borrow_mut().insert(key, entry));
    let mut bytes = [0u8; 16];
    PREFIX.with(|p| bytes[..8].copy_from_slice(p));
    bytes[8..].copy_from_slice(&suffix);
    let seg = |i: usize| u16::from_be_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    VIpAddress::Ipv6((
        seg(0),
        seg(1),
        seg(2),
        seg(3),
        seg(4),
        seg(5),
        seg(6),
        seg(7),
    ))
}

/// The table entry a handle socket-address refers to, if it is one.
fn lookup_handle(remote: &VIpSocketAddress) -> Option<(String, Vec<host::IpAddress>, u16)> {
    let VIpSocketAddress::Ipv6(v6) = remote else {
        return None;
    };
    let (a, b, c, d, e, f, g, h) = v6.address;
    let mut bytes = [0u8; 16];
    for (i, seg) in [a, b, c, d, e, f, g, h].into_iter().enumerate() {
        bytes[2 * i..2 * i + 2].copy_from_slice(&seg.to_be_bytes());
    }
    let is_ours = PREFIX.with(|p| &bytes[..8] == p);
    if !is_ours {
        return None;
    }
    let key = u64::from_be_bytes(bytes[8..].try_into().unwrap());
    TABLE.with(|t| {
        t.borrow()
            .get(&key)
            .map(|e| (e.hostname.clone(), e.addrs.clone(), v6.port))
    })
}

struct Component;

virt_bindings::export!(Component with_types_in virt_bindings);

impl TypesGuest for Component {
    type TcpSocket = VTcp;
    type UdpSocket = VUdp;
}

impl LookupGuest for Component {
    async fn resolve_addresses(name: String) -> Result<Vec<VIpAddress>, VLookupErrorCode> {
        match name.strip_suffix(SUFFIX) {
            Some(real) => {
                let real = real.to_string();
                let addrs = host_lookup::resolve_addresses(real.clone())
                    .await
                    .map_err(lookup_to_v)?;
                if addrs.is_empty() {
                    return Err(VLookupErrorCode::NameUnresolvable);
                }
                Ok(vec![mint_handle(Entry {
                    hostname: real,
                    addrs,
                })])
            }
            None => Ok(host_lookup::resolve_addresses(name)
                .await
                .map_err(lookup_to_v)?
                .into_iter()
                .map(addr_to_v)
                .collect()),
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
type VVerdict = FutureReader<Result<(), VErrorCode>>;

/// Task-scope note: every long-lived tunnel task (the transmit splice and
/// the verdict mappers) is spawned inside `connect`, the one async-lifted
/// export on this path. wit-bindgen spawns only run within an async
/// export's task scope; a spawn from a sync-lifted export (`send`,
/// `receive`) is queued but never polled. The sync exports therefore only
/// hand out endpoints created at connect time.
struct Tunnel {
    /// The handle address the application dialed, for `get-remote-address`.
    remote: VIpSocketAddress,
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
    fn host_op<T>(&self, op: impl FnOnce(&host::TcpSocket) -> T) -> Result<T, VErrorCode> {
        match &*self.state.borrow() {
            TcpState::Host(s) => Ok(op(s)),
            TcpState::Tunnel(t) => Ok(op(&t.host)),
            TcpState::Busy => Err(VErrorCode::InvalidState),
        }
    }
}

impl GuestTcpSocket for VTcp {
    fn create(address_family: VFamily) -> Result<VTcpSocketResource, VErrorCode> {
        let socket = host::TcpSocket::create(family_to_host(address_family)).map_err(err_to_v)?;
        Ok(VTcpSocketResource::new(VTcp {
            state: RefCell::new(TcpState::Host(socket)),
        }))
    }

    fn bind(&self, local_address: VIpSocketAddress) -> Result<(), VErrorCode> {
        self.host_op(|s| s.bind(sockaddr_to_host(local_address)).map_err(err_to_v))?
    }

    async fn connect(&self, remote_address: VIpSocketAddress) -> Result<(), VErrorCode> {
        let Some((hostname, addrs, port)) = lookup_handle(&remote_address) else {
            // Pass-through. Take the socket out so the borrow does not
            // span the await.
            let state = std::mem::replace(&mut *self.state.borrow_mut(), TcpState::Busy);
            let TcpState::Host(socket) = state else {
                *self.state.borrow_mut() = state;
                return Err(VErrorCode::InvalidState);
            };
            let result = socket
                .connect(sockaddr_to_host(remote_address))
                .await
                .map_err(err_to_v);
            *self.state.borrow_mut() = TcpState::Host(socket);
            return result;
        };

        // Tunnel path: connect the real transport.
        let real_addr = pick_addr(&addrs, port).ok_or(VErrorCode::RemoteUnreachable)?;
        let real = host::TcpSocket::create(match &real_addr {
            host::IpSocketAddress::Ipv4(_) => host::IpAddressFamily::Ipv4,
            host::IpSocketAddress::Ipv6(_) => host::IpAddressFamily::Ipv6,
        })
        .map_err(err_to_v)?;
        real.connect(real_addr).await.map_err(err_to_v)?;

        // Wire the TLS transforms: ciphertext straight onto the socket,
        // application transmit through a pipe (its stream arrives later,
        // at `send`).
        let connector = Connector::new(&ROOTS.iter().map(|r| r.to_vec()).collect::<Vec<_>>());
        let (pipe_writer, pipe_reader) = host_bindings::wit_stream::new();
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
                VErrorCode::ConnectionReset
            })?;

        // The long-lived tunnel tasks, spawned here so they live in this
        // async export's task scope (see the note on `Tunnel`). This task
        // stays alive until they finish, which is when both TLS
        // directions have ended.
        let (send_verdict_writer, send_verdict) = virt_bindings::wit_future::new::<
            Result<(), VErrorCode>,
        >(|| Err(VErrorCode::Other(None)));
        let (recv_verdict_writer, recv_verdict) = virt_bindings::wit_future::new::<
            Result<(), VErrorCode>,
        >(|| Err(VErrorCode::Other(None)));
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
                VErrorCode::ConnectionReset
            });
            let _ = send_verdict_writer.write(result).await;
        });

        wit_bindgen::spawn_local(async move {
            let result = recv_done.await.map_err(|e| {
                eprintln!(
                    "tls-virt: receive direction failed: {}",
                    e.to_debug_string()
                );
                VErrorCode::ConnectionReset
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
            TcpState::Host(s) => rewrap_verdict(s.send(data)),
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
            TcpState::Host(s) => {
                let (stream, host_done) = s.receive();
                (stream, rewrap_verdict(host_done))
            }
            TcpState::Tunnel(t) => match t.cleartext.take() {
                Some(pair) => pair,
                None => closed_receive(),
            },
            TcpState::Busy => closed_receive(),
        }
    }

    fn listen(&self) -> Result<StreamReader<VTcpSocketResource>, VErrorCode> {
        // Wrapping each accepted host socket into an exported resource
        // needs a live task, and this sync-lifted export has no task
        // scope to host one (see the note on `Tunnel` and README.md).
        eprintln!("tls-virt: listen is not supported");
        Err(VErrorCode::NotSupported)
    }

    fn get_local_address(&self) -> Result<VIpSocketAddress, VErrorCode> {
        self.host_op(|s| s.get_local_address().map(sockaddr_to_v).map_err(err_to_v))?
    }

    fn get_remote_address(&self) -> Result<VIpSocketAddress, VErrorCode> {
        match &*self.state.borrow() {
            // Preserve the illusion: the application dialed the handle.
            TcpState::Tunnel(t) => Ok(t.remote),
            TcpState::Host(s) => s.get_remote_address().map(sockaddr_to_v).map_err(err_to_v),
            TcpState::Busy => Err(VErrorCode::InvalidState),
        }
    }

    fn get_is_listening(&self) -> bool {
        self.host_op(|s| s.get_is_listening()).unwrap_or(false)
    }

    fn get_address_family(&self) -> VFamily {
        match &*self.state.borrow() {
            TcpState::Tunnel(_) => VFamily::Ipv6,
            TcpState::Host(s) => family_to_v(s.get_address_family()),
            TcpState::Busy => VFamily::Ipv6,
        }
    }

    fn set_listen_backlog_size(&self, value: u64) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_listen_backlog_size(value).map_err(err_to_v))?
    }

    fn get_keep_alive_enabled(&self) -> Result<bool, VErrorCode> {
        self.host_op(|s| s.get_keep_alive_enabled().map_err(err_to_v))?
    }

    fn set_keep_alive_enabled(&self, value: bool) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_keep_alive_enabled(value).map_err(err_to_v))?
    }

    fn get_keep_alive_idle_time(&self) -> Result<u64, VErrorCode> {
        self.host_op(|s| s.get_keep_alive_idle_time().map_err(err_to_v))?
    }

    fn set_keep_alive_idle_time(&self, value: u64) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_keep_alive_idle_time(value).map_err(err_to_v))?
    }

    fn get_keep_alive_interval(&self) -> Result<u64, VErrorCode> {
        self.host_op(|s| s.get_keep_alive_interval().map_err(err_to_v))?
    }

    fn set_keep_alive_interval(&self, value: u64) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_keep_alive_interval(value).map_err(err_to_v))?
    }

    fn get_keep_alive_count(&self) -> Result<u32, VErrorCode> {
        self.host_op(|s| s.get_keep_alive_count().map_err(err_to_v))?
    }

    fn set_keep_alive_count(&self, value: u32) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_keep_alive_count(value).map_err(err_to_v))?
    }

    fn get_hop_limit(&self) -> Result<u8, VErrorCode> {
        self.host_op(|s| s.get_hop_limit().map_err(err_to_v))?
    }

    fn set_hop_limit(&self, value: u8) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_hop_limit(value).map_err(err_to_v))?
    }

    fn get_receive_buffer_size(&self) -> Result<u64, VErrorCode> {
        self.host_op(|s| s.get_receive_buffer_size().map_err(err_to_v))?
    }

    fn set_receive_buffer_size(&self, value: u64) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_receive_buffer_size(value).map_err(err_to_v))?
    }

    fn get_send_buffer_size(&self) -> Result<u64, VErrorCode> {
        self.host_op(|s| s.get_send_buffer_size().map_err(err_to_v))?
    }

    fn set_send_buffer_size(&self, value: u64) -> Result<(), VErrorCode> {
        self.host_op(|s| s.set_send_buffer_size(value).map_err(err_to_v))?
    }
}

/// Reissues a host-side transport verdict as an export-side one, by
/// handle. The payload types are structural byte-copies of one WIT type,
/// so the transfer type-checks at the boundary; this component never
/// reads the future, it only passes it out.
fn rewrap_verdict(host: FutureReader<Result<(), host::ErrorCode>>) -> VVerdict {
    use virt_bindings::wit_future::FuturePayload;
    // SAFETY: `take_handle` yields ownership of a live future handle, and
    // the vtable's wire representation for the two payload types is
    // identical.
    unsafe { FutureReader::new(host.take_handle(), <Result<(), VErrorCode>>::VTABLE) }
}

/// A verdict already resolved to `err(invalid-state)`: the writer drops
/// unused, so the reader observes the default value.
fn invalid_state_verdict() -> VVerdict {
    let (writer, reader) =
        virt_bindings::wit_future::new::<Result<(), VErrorCode>>(|| Err(VErrorCode::InvalidState));
    drop(writer);
    reader
}

/// A receive pair for sockets with nothing to give: an already-closed
/// stream and an invalid-state verdict.
fn closed_receive() -> (StreamReader<u8>, VVerdict) {
    let (stream_writer, stream_reader) = virt_bindings::wit_stream::new::<u8>();
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
    fn create(address_family: VFamily) -> Result<VUdpSocketResource, VErrorCode> {
        let socket = host::UdpSocket::create(family_to_host(address_family)).map_err(err_to_v)?;
        Ok(VUdpSocketResource::new(VUdp { inner: socket }))
    }

    fn bind(&self, local_address: VIpSocketAddress) -> Result<(), VErrorCode> {
        self.inner
            .bind(sockaddr_to_host(local_address))
            .map_err(err_to_v)
    }

    fn connect(&self, remote_address: VIpSocketAddress) -> Result<(), VErrorCode> {
        self.inner
            .connect(sockaddr_to_host(remote_address))
            .map_err(err_to_v)
    }

    fn disconnect(&self) -> Result<(), VErrorCode> {
        self.inner.disconnect().map_err(err_to_v)
    }

    async fn send(
        &self,
        data: Vec<u8>,
        remote_address: Option<VIpSocketAddress>,
    ) -> Result<(), VErrorCode> {
        self.inner
            .send(data, remote_address.map(sockaddr_to_host))
            .await
            .map_err(err_to_v)
    }

    async fn receive(&self) -> Result<(Vec<u8>, VIpSocketAddress), VErrorCode> {
        self.inner
            .receive()
            .await
            .map(|(data, addr)| (data, sockaddr_to_v(addr)))
            .map_err(err_to_v)
    }

    fn get_local_address(&self) -> Result<VIpSocketAddress, VErrorCode> {
        self.inner
            .get_local_address()
            .map(sockaddr_to_v)
            .map_err(err_to_v)
    }

    fn get_remote_address(&self) -> Result<VIpSocketAddress, VErrorCode> {
        self.inner
            .get_remote_address()
            .map(sockaddr_to_v)
            .map_err(err_to_v)
    }

    fn get_address_family(&self) -> VFamily {
        family_to_v(self.inner.get_address_family())
    }

    fn get_unicast_hop_limit(&self) -> Result<u8, VErrorCode> {
        self.inner.get_unicast_hop_limit().map_err(err_to_v)
    }

    fn set_unicast_hop_limit(&self, value: u8) -> Result<(), VErrorCode> {
        self.inner.set_unicast_hop_limit(value).map_err(err_to_v)
    }

    fn get_receive_buffer_size(&self) -> Result<u64, VErrorCode> {
        self.inner.get_receive_buffer_size().map_err(err_to_v)
    }

    fn set_receive_buffer_size(&self, value: u64) -> Result<(), VErrorCode> {
        self.inner.set_receive_buffer_size(value).map_err(err_to_v)
    }

    fn get_send_buffer_size(&self) -> Result<u64, VErrorCode> {
        self.inner.get_send_buffer_size().map_err(err_to_v)
    }

    fn set_send_buffer_size(&self, value: u64) -> Result<(), VErrorCode> {
        self.inner.set_send_buffer_size(value).map_err(err_to_v)
    }
}

// --- type mapping between the imported and exported interfaces ---

fn family_to_host(family: VFamily) -> host::IpAddressFamily {
    match family {
        VFamily::Ipv4 => host::IpAddressFamily::Ipv4,
        VFamily::Ipv6 => host::IpAddressFamily::Ipv6,
    }
}

fn family_to_v(family: host::IpAddressFamily) -> VFamily {
    match family {
        host::IpAddressFamily::Ipv4 => VFamily::Ipv4,
        host::IpAddressFamily::Ipv6 => VFamily::Ipv6,
    }
}

fn addr_to_v(addr: host::IpAddress) -> VIpAddress {
    match addr {
        host::IpAddress::Ipv4(a) => VIpAddress::Ipv4(a),
        host::IpAddress::Ipv6(a) => VIpAddress::Ipv6(a),
    }
}

fn sockaddr_to_host(addr: VIpSocketAddress) -> host::IpSocketAddress {
    match addr {
        VIpSocketAddress::Ipv4(v4) => host::IpSocketAddress::Ipv4(host::Ipv4SocketAddress {
            port: v4.port,
            address: v4.address,
        }),
        VIpSocketAddress::Ipv6(v6) => host::IpSocketAddress::Ipv6(host::Ipv6SocketAddress {
            port: v6.port,
            flow_info: v6.flow_info,
            address: v6.address,
            scope_id: v6.scope_id,
        }),
    }
}

fn sockaddr_to_v(addr: host::IpSocketAddress) -> VIpSocketAddress {
    match addr {
        host::IpSocketAddress::Ipv4(v4) => VIpSocketAddress::Ipv4(VIpv4SocketAddress {
            port: v4.port,
            address: v4.address,
        }),
        host::IpSocketAddress::Ipv6(v6) => VIpSocketAddress::Ipv6(VIpv6SocketAddress {
            port: v6.port,
            flow_info: v6.flow_info,
            address: v6.address,
            scope_id: v6.scope_id,
        }),
    }
}

/// A destination socket-address from a resolved entry, preferring IPv6.
fn pick_addr(addrs: &[host::IpAddress], port: u16) -> Option<host::IpSocketAddress> {
    let v6 = addrs.iter().find_map(|a| match a {
        host::IpAddress::Ipv6(seg) => Some(host::IpSocketAddress::Ipv6(host::Ipv6SocketAddress {
            port,
            flow_info: 0,
            address: *seg,
            scope_id: 0,
        })),
        _ => None,
    });
    v6.or_else(|| {
        addrs.iter().find_map(|a| match a {
            host::IpAddress::Ipv4(oct) => {
                Some(host::IpSocketAddress::Ipv4(host::Ipv4SocketAddress {
                    port,
                    address: *oct,
                }))
            }
            _ => None,
        })
    })
}

fn err_to_v(code: host::ErrorCode) -> VErrorCode {
    match code {
        host::ErrorCode::AccessDenied => VErrorCode::AccessDenied,
        host::ErrorCode::NotSupported => VErrorCode::NotSupported,
        host::ErrorCode::InvalidArgument => VErrorCode::InvalidArgument,
        host::ErrorCode::OutOfMemory => VErrorCode::OutOfMemory,
        host::ErrorCode::Timeout => VErrorCode::Timeout,
        host::ErrorCode::InvalidState => VErrorCode::InvalidState,
        host::ErrorCode::AddressNotBindable => VErrorCode::AddressNotBindable,
        host::ErrorCode::AddressInUse => VErrorCode::AddressInUse,
        host::ErrorCode::RemoteUnreachable => VErrorCode::RemoteUnreachable,
        host::ErrorCode::ConnectionRefused => VErrorCode::ConnectionRefused,
        host::ErrorCode::ConnectionBroken => VErrorCode::ConnectionBroken,
        host::ErrorCode::ConnectionReset => VErrorCode::ConnectionReset,
        host::ErrorCode::ConnectionAborted => VErrorCode::ConnectionAborted,
        host::ErrorCode::DatagramTooLarge => VErrorCode::DatagramTooLarge,
        host::ErrorCode::Other(detail) => VErrorCode::Other(detail),
    }
}

fn lookup_to_v(code: host_lookup::ErrorCode) -> VLookupErrorCode {
    match code {
        host_lookup::ErrorCode::AccessDenied => VLookupErrorCode::AccessDenied,
        host_lookup::ErrorCode::InvalidArgument => VLookupErrorCode::InvalidArgument,
        host_lookup::ErrorCode::NameUnresolvable => VLookupErrorCode::NameUnresolvable,
        host_lookup::ErrorCode::TemporaryResolverFailure => {
            VLookupErrorCode::TemporaryResolverFailure
        }
        host_lookup::ErrorCode::PermanentResolverFailure => {
            VLookupErrorCode::PermanentResolverFailure
        }
        host_lookup::ErrorCode::Other(detail) => VLookupErrorCode::Other(detail),
    }
}
