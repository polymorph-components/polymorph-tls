//! `wasi:sockets@0.2.x` interposition: the same tls-virt scheme served
//! to WASI 0.2 guests — which includes every component built from plain
//! Rust `std::net` code, since std on wasm32-wasip2 sits on these
//! interfaces.
//!
//! Only `sockets/tcp` and `sockets/ip-name-lookup` carry custom
//! implementations; `udp`, `network`, `instance-network`, and the
//! create-socket interfaces are registered directly against
//! wasmtime-wasi's (see `main.rs`). Pass-through operations delegate
//! per method exactly like the 0.3 provider.
//!
//! The 0.2 shapes change the tunnel plumbing:
//!
//! - `start-connect`/`finish-connect` are a two-phase, poll-driven
//!   pair: start spawns the TCP+TLS handshake as a background task;
//!   finish reports would-block until it resolves; `subscribe` on a
//!   tunnel socket returns a pollable over the handshake's completion
//!   (a fresh owned table entry per call, so the pollable's lifetime
//!   manages it).
//! - The data path is `wasi:io` streams, not component-model streams:
//!   the returned input/output streams are this module's
//!   [`TlsInputStream`]/[`TlsOutputStream`], byte buffers over the TLS
//!   halves whose IO is driven inside `Pollable::ready`. Stream state
//!   is shared with the socket through `Arc<Mutex<…>>` slots so that
//!   `tcp-socket.shutdown` can reach the halves.
//! - close_notify: `shutdown(send)` (what `std::net`'s
//!   `Shutdown::Write` becomes) and dropping the output stream both
//!   drive the TLS shutdown — spawned onto the runtime when requested
//!   from a sync context.
//! - A clean TLS end surfaces as end-of-stream (`closed`); a transport
//!   close without close_notify surfaces as a stream error, never as
//!   end-of-data.
//! - Name lookup returns a `resolve-address-stream` resource, so the
//!   suffix seam wraps it: the inner resolution is delegated (address
//!   policy included), its results are drained through the wrapped
//!   resource, and the stream yields exactly one minted handle address.
//!
//! Unlike the 0.3 tunnel path, tunneled connects here **do** pass the
//! sandbox's address check: the 0.2 `network` resource exposes
//! `check_socket_addr` publicly, and `start-connect` runs it against
//! the real destination before dialing.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::watch;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::sockets::ip_name_lookup::{
    Host as LookupHost, HostResolveAddressStream, ResolveAddressStream,
};
use wasmtime_wasi::p2::bindings::sockets::network::{
    self as network, ErrorCode, IpAddress, IpSocketAddress, Network,
};
use wasmtime_wasi::p2::bindings::sockets::tcp::{
    self, HostTcpSocket, IpAddressFamily, ShutdownType,
};
use wasmtime_wasi::p2::{
    subscribe, DynInputStream, DynOutputStream, DynPollable, InputStream, OutputStream, Pollable,
    SocketError, SocketResult, StreamError, StreamResult,
};
use wasmtime_wasi::sockets::{SocketAddrUse, TcpSocket};

use tls_virt_common::Entry;

use crate::{VirtView, CHUNK};

type TlsReadHalf = crate::TlsReadHalf;
type TlsWriteHalf = crate::TlsWriteHalf;

/// A 0.2 tunnel, keyed (like the 0.3 side map) by the socket resource's
/// table index.
pub(crate) enum P2Tunnel {
    /// The handshake task is in flight; `finish-connect` polls the slot.
    Connecting {
        remote: IpSocketAddress,
        ready: watch::Receiver<bool>,
        result: Arc<Mutex<Option<Result<TlsParts, ErrorCode>>>>,
    },
    Connected(Connected),
    /// `finish-connect` already reported the handshake failure.
    Failed,
}

/// What the handshake task delivers.
pub(crate) struct TlsParts {
    local: Option<SocketAddr>,
    read: TlsReadHalf,
    write: TlsWriteHalf,
}

pub(crate) struct Connected {
    remote: IpSocketAddress,
    local: Option<SocketAddr>,
    /// Always-true readiness, for `subscribe` on a connected socket.
    ready: watch::Receiver<bool>,
    read: ReadShared,
    write: WriteShared,
}

/// A suffix-opted resolution being drained through the wrapped
/// `resolve-address-stream`, keyed by the delegated resource's table
/// index.
pub(crate) enum P2Resolve {
    Draining {
        hostname: String,
        addrs: Vec<IpAddr>,
    },
    Yielded,
}

// --- the TLS-backed wasi:io streams ---

type ReadShared = Arc<Mutex<ReadSlot>>;

struct ReadSlot {
    /// Taken while an async read is in flight inside `ready`.
    half: Option<TlsReadHalf>,
    buf: BytesMut,
    state: StreamState,
}

enum StreamState {
    Open,
    /// Clean end: close_notify in the receive direction, shutdown
    /// complete in the send direction.
    Closed,
    Failed(String),
}

impl StreamState {
    fn check(&self) -> StreamResult<()> {
        match self {
            StreamState::Open => Ok(()),
            StreamState::Closed => Err(StreamError::Closed),
            StreamState::Failed(message) => Err(StreamError::LastOperationFailed(
                wasmtime::format_err!("{message}"),
            )),
        }
    }
}

/// The guest's receive stream: decrypted bytes from the TLS read half.
/// Pull-driven: reads happen inside `Pollable::ready`, which 0.2 guests
/// drive whenever they want data.
struct TlsInputStream {
    shared: ReadShared,
}

impl InputStream for TlsInputStream {
    fn read(&mut self, size: usize) -> StreamResult<Bytes> {
        let mut slot = self.shared.lock().unwrap();
        if !slot.buf.is_empty() {
            let n = slot.buf.len().min(size);
            return Ok(slot.buf.split_to(n).freeze());
        }
        slot.state.check()?;
        Ok(Bytes::new())
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for TlsInputStream {
    async fn ready(&mut self) {
        let mut half = {
            let mut slot = self.shared.lock().unwrap();
            if !slot.buf.is_empty() || !matches!(slot.state, StreamState::Open) {
                return;
            }
            match slot.half.take() {
                Some(half) => half,
                None => return,
            }
        };
        let mut buf = vec![0u8; CHUNK];
        let result = half.read(&mut buf).await;
        let mut slot = self.shared.lock().unwrap();
        match result {
            // Clean TLS end: the peer sent close_notify.
            Ok(0) => slot.state = StreamState::Closed,
            Ok(n) => {
                slot.buf.extend_from_slice(&buf[..n]);
                slot.half = Some(half);
            }
            Err(e) => {
                eprintln!("tls-virt-wasmtime: receive direction failed: {e}");
                slot.state = StreamState::Failed(format!("TLS receive failed: {e}"));
            }
        }
    }
}

type WriteShared = Arc<WriteCtl>;

/// Send-direction state shared between the guest-facing stream, the
/// socket (for `shutdown(send)`), and the writer task.
struct WriteCtl {
    inner: Mutex<WriteInner>,
    /// Guest -> task: new bytes, a flush, or a shutdown request.
    wake: tokio::sync::Notify,
    /// Task -> guest: budget freed, flush completed, or a terminal
    /// state; what `Pollable::ready` waits on.
    ready: tokio::sync::Notify,
}

struct WriteInner {
    /// Guest-written bytes the task has not yet taken.
    queued: BytesMut,
    /// `check-write` reports no budget until the requested flush
    /// completes.
    flushing: bool,
    /// close_notify requested (`shutdown(send)` or output-stream
    /// drop); the task performs it after draining the queue.
    shutdown: bool,
    state: StreamState,
}

impl WriteCtl {
    fn new() -> WriteShared {
        Arc::new(WriteCtl {
            inner: Mutex::new(WriteInner {
                queued: BytesMut::new(),
                flushing: false,
                shutdown: false,
                state: StreamState::Open,
            }),
            wake: tokio::sync::Notify::new(),
            ready: tokio::sync::Notify::new(),
        })
    }
}

/// The writer task: owns the TLS write half and drains the queue. A 0.2
/// guest is allowed to `check-write`/`write` and never poll again, so
/// the send direction must make progress on its own; this task is that
/// progress. It ends after performing the TLS shutdown (close_notify)
/// or on a send error.
async fn write_task(ctl: WriteShared, mut half: TlsWriteHalf) {
    enum Work {
        Io(BytesMut, bool, bool),
        Wait,
        End,
    }
    fn next_work(ctl: &WriteCtl) -> Work {
        let mut inner = ctl.inner.lock().unwrap();
        if !matches!(inner.state, StreamState::Open) {
            return Work::End;
        }
        if inner.queued.is_empty() && !inner.flushing && !inner.shutdown {
            return Work::Wait;
        }
        let len = inner.queued.len();
        Work::Io(inner.queued.split_to(len), inner.flushing, inner.shutdown)
    }
    loop {
        let (chunk, flushing, shutdown) = match next_work(&ctl) {
            Work::End => return,
            Work::Wait => {
                let wake = ctl.wake.notified();
                tokio::pin!(wake);
                wake.as_mut().enable();
                // Re-check after registering interest: a request that
                // landed in between is caught here, one that lands
                // after is buffered by the notify.
                if matches!(next_work(&ctl), Work::Wait) {
                    wake.await;
                }
                continue;
            }
            Work::Io(chunk, flushing, shutdown) => (chunk, flushing, shutdown),
        };

        let mut result = half.write_all(&chunk).await;
        if result.is_ok() && flushing {
            result = half.flush().await;
        }
        if result.is_ok() && shutdown {
            // close_notify, then flush and FIN.
            result = half.shutdown().await;
        }

        let mut inner = ctl.inner.lock().unwrap();
        match result {
            Ok(()) => {
                if flushing && inner.queued.is_empty() {
                    inner.flushing = false;
                }
                if shutdown {
                    inner.state = StreamState::Closed;
                    ctl.ready.notify_waiters();
                    return;
                }
            }
            Err(e) => {
                eprintln!("tls-virt-wasmtime: send direction failed: {e}");
                inner.state = StreamState::Failed(format!("TLS send failed: {e}"));
                ctl.ready.notify_waiters();
                return;
            }
        }
        ctl.ready.notify_waiters();
    }
}

/// The guest's transmit stream: cleartext handed to the writer task.
struct TlsOutputStream {
    shared: WriteShared,
}

impl OutputStream for TlsOutputStream {
    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        let mut inner = self.shared.inner.lock().unwrap();
        inner.state.check()?;
        if inner.shutdown {
            return Err(StreamError::Closed);
        }
        let permitted = if inner.flushing {
            0
        } else {
            CHUNK.saturating_sub(inner.queued.len())
        };
        if bytes.len() > permitted {
            return Err(StreamError::trap("write exceeds check-write permit"));
        }
        inner.queued.extend_from_slice(&bytes);
        drop(inner);
        self.shared.wake.notify_one();
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        let mut inner = self.shared.inner.lock().unwrap();
        inner.state.check()?;
        if inner.shutdown {
            return Err(StreamError::Closed);
        }
        inner.flushing = true;
        drop(inner);
        self.shared.wake.notify_one();
        Ok(())
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        let inner = self.shared.inner.lock().unwrap();
        inner.state.check()?;
        if inner.shutdown {
            return Err(StreamError::Closed);
        }
        if inner.flushing {
            Ok(0)
        } else {
            Ok(CHUNK.saturating_sub(inner.queued.len()))
        }
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for TlsOutputStream {
    async fn ready(&mut self) {
        loop {
            let notified = self.shared.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let inner = self.shared.inner.lock().unwrap();
                let writable = !inner.flushing && inner.queued.len() < CHUNK;
                if writable || !matches!(inner.state, StreamState::Open) || inner.shutdown {
                    return;
                }
            }
            notified.await;
        }
    }
}

impl Drop for TlsOutputStream {
    fn drop(&mut self) {
        // The guest released its transmit stream: close the send
        // direction with close_notify, unless it already ended.
        request_shutdown(&self.shared);
    }
}

/// Requests close_notify on the send direction; the writer task
/// performs it once the queue drains.
fn request_shutdown(shared: &WriteShared) {
    let mut inner = shared.inner.lock().unwrap();
    if !matches!(inner.state, StreamState::Open) || inner.shutdown {
        return;
    }
    inner.shutdown = true;
    drop(inner);
    shared.wake.notify_one();
}

/// Closes the receive direction: any buffered cleartext is discarded
/// and the read half drops.
fn close_read(shared: &ReadShared) {
    let mut slot = shared.lock().unwrap();
    slot.half = None;
    slot.buf.clear();
    if matches!(slot.state, StreamState::Open) {
        slot.state = StreamState::Closed;
    }
}

/// Readiness of a tunnel socket, as handed to `subscribe`: resolves
/// when the handshake outcome is available (immediately for
/// established or failed tunnels). A fresh owned entry per `subscribe`
/// call; the pollable's lifetime manages it.
struct TunnelReady(watch::Receiver<bool>);

#[wasmtime_wasi::async_trait]
impl Pollable for TunnelReady {
    async fn ready(&mut self) {
        // A dropped sender (handshake task failure) also means the
        // outcome — an empty slot — is observable.
        let _ = self.0.wait_for(|done| *done).await;
    }
}

// --- conversions between the 0.2 generated types and std ---

fn ip_to_std(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6(s) => IpAddr::V6(std::net::Ipv6Addr::new(
            s.0, s.1, s.2, s.3, s.4, s.5, s.6, s.7,
        )),
    }
}

fn handle_to_ip(handle: std::net::Ipv6Addr) -> IpAddress {
    let s = handle.segments();
    IpAddress::Ipv6((s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
}

// --- sockets/network (a required bound of the interposed interfaces:
// their types come from it) ---

impl network::Host for VirtView<'_> {
    fn convert_error_code(&mut self, error: SocketError) -> wasmtime::Result<ErrorCode> {
        network::Host::convert_error_code(&mut self.sockets, error)
    }

    fn network_error_code(
        &mut self,
        err: Resource<wasmtime::Error>,
    ) -> wasmtime::Result<Option<ErrorCode>> {
        network::Host::network_error_code(&mut self.sockets, err)
    }
}

impl network::HostNetwork for VirtView<'_> {
    fn drop(&mut self, this: Resource<Network>) -> wasmtime::Result<()> {
        network::HostNetwork::drop(&mut self.sockets, this)
    }
}

// --- sockets/tcp ---

impl tcp::Host for VirtView<'_> {}

impl HostTcpSocket for VirtView<'_> {
    async fn start_bind(
        &mut self,
        this: Resource<TcpSocket>,
        network: Resource<Network>,
        local_address: IpSocketAddress,
    ) -> SocketResult<()> {
        HostTcpSocket::start_bind(&mut self.sockets, this, network, local_address).await
    }

    fn finish_bind(&mut self, this: Resource<TcpSocket>) -> SocketResult<()> {
        HostTcpSocket::finish_bind(&mut self.sockets, this)
    }

    async fn start_connect(
        &mut self,
        this: Resource<TcpSocket>,
        network: Resource<Network>,
        remote_address: IpSocketAddress,
    ) -> SocketResult<()> {
        let dialed: SocketAddr = remote_address.into();
        let entry = match dialed.ip() {
            IpAddr::V6(v6) => self
                .virt
                .names
                .lookup(&v6)
                .map(|e| (e.hostname.clone(), e.addrs.clone())),
            IpAddr::V4(_) => None,
        };
        let Some((hostname, addrs)) = entry else {
            return HostTcpSocket::start_connect(&mut self.sockets, this, network, remote_address)
                .await;
        };

        if self.virt.p2_tunnels.contains_key(&this.rep()) {
            return Err(ErrorCode::InvalidState.into());
        }
        let addr = tls_virt_common::pick_addr(&addrs, dialed.port())
            .ok_or(ErrorCode::RemoteUnreachable)?;

        // Unlike the 0.3 path, the sandbox's address check is reachable
        // here: run it against the real destination.
        let net = self.sockets.table.get(&network)?;
        net.check_socket_addr(addr, SocketAddrUse::TcpConnect)
            .await
            .map_err(|_| ErrorCode::AccessDenied)?;

        let connector = self.virt.connector.clone();
        let (done_tx, done_rx) = watch::channel(false);
        let result: Arc<Mutex<Option<Result<TlsParts, ErrorCode>>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&result);
        self.virt.runtime.spawn(async move {
            let outcome = async {
                let stream = TcpStream::connect(addr).await.map_err(ErrorCode::from)?;
                let local = stream.local_addr().ok();
                let server_name = ServerName::try_from(hostname.clone())
                    .map_err(|_| ErrorCode::InvalidArgument)?;
                let tls = connector.connect(server_name, stream).await.map_err(|e| {
                    eprintln!("tls-virt-wasmtime: TLS handshake with {hostname:?} failed: {e}");
                    ErrorCode::ConnectionReset
                })?;
                let (read, write) = tokio::io::split(tls);
                Ok(TlsParts { local, read, write })
            }
            .await;
            *slot.lock().unwrap() = Some(outcome);
            let _ = done_tx.send(true);
        });

        self.virt.p2_tunnels.insert(
            this.rep(),
            P2Tunnel::Connecting {
                remote: remote_address,
                ready: done_rx,
                result,
            },
        );
        Ok(())
    }

    fn finish_connect(
        &mut self,
        this: Resource<TcpSocket>,
    ) -> SocketResult<(Resource<DynInputStream>, Resource<DynOutputStream>)> {
        let rep = this.rep();
        let Some(tunnel) = self.virt.p2_tunnels.get_mut(&rep) else {
            return HostTcpSocket::finish_connect(&mut self.sockets, this);
        };
        let P2Tunnel::Connecting {
            remote,
            ready,
            result,
        } = tunnel
        else {
            return Err(ErrorCode::NotInProgress.into());
        };
        let outcome = result.lock().unwrap().take().ok_or(ErrorCode::WouldBlock)?;
        let remote = *remote;
        let ready = ready.clone();
        let parts = match outcome {
            Ok(parts) => parts,
            Err(code) => {
                *tunnel = P2Tunnel::Failed;
                return Err(code.into());
            }
        };

        let read: ReadShared = Arc::new(Mutex::new(ReadSlot {
            half: Some(parts.read),
            buf: BytesMut::new(),
            state: StreamState::Open,
        }));
        let write = WriteCtl::new();
        self.virt
            .runtime
            .spawn(write_task(Arc::clone(&write), parts.write));
        *tunnel = P2Tunnel::Connected(Connected {
            remote,
            local: parts.local,
            ready,
            read: Arc::clone(&read),
            write: Arc::clone(&write),
        });

        let input: DynInputStream = Box::new(TlsInputStream { shared: read });
        let output: DynOutputStream = Box::new(TlsOutputStream { shared: write });
        let input = self.sockets.table.push_child(input, &this)?;
        let output = self.sockets.table.push_child(output, &this)?;
        Ok((input, output))
    }

    fn start_listen(&mut self, this: Resource<TcpSocket>) -> SocketResult<()> {
        HostTcpSocket::start_listen(&mut self.sockets, this)
    }

    fn finish_listen(&mut self, this: Resource<TcpSocket>) -> SocketResult<()> {
        HostTcpSocket::finish_listen(&mut self.sockets, this)
    }

    fn accept(
        &mut self,
        this: Resource<TcpSocket>,
    ) -> SocketResult<(
        Resource<TcpSocket>,
        Resource<DynInputStream>,
        Resource<DynOutputStream>,
    )> {
        HostTcpSocket::accept(&mut self.sockets, this)
    }

    fn local_address(&mut self, this: Resource<TcpSocket>) -> SocketResult<IpSocketAddress> {
        match self.virt.p2_tunnels.get(&this.rep()) {
            Some(P2Tunnel::Connected(c)) => match c.local {
                Some(addr) => Ok(addr.into()),
                None => Err(ErrorCode::InvalidState.into()),
            },
            Some(_) => Err(ErrorCode::InvalidState.into()),
            None => HostTcpSocket::local_address(&mut self.sockets, this),
        }
    }

    fn remote_address(&mut self, this: Resource<TcpSocket>) -> SocketResult<IpSocketAddress> {
        // Preserve the illusion: the guest dialed the handle.
        match self.virt.p2_tunnels.get(&this.rep()) {
            Some(P2Tunnel::Connected(c)) => Ok(c.remote),
            Some(_) => Err(ErrorCode::InvalidState.into()),
            None => HostTcpSocket::remote_address(&mut self.sockets, this),
        }
    }

    fn is_listening(&mut self, this: Resource<TcpSocket>) -> wasmtime::Result<bool> {
        HostTcpSocket::is_listening(&mut self.sockets, this)
    }

    fn address_family(&mut self, this: Resource<TcpSocket>) -> wasmtime::Result<IpAddressFamily> {
        HostTcpSocket::address_family(&mut self.sockets, this)
    }

    fn set_listen_backlog_size(
        &mut self,
        this: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_listen_backlog_size(&mut self.sockets, this, value)
    }

    fn keep_alive_enabled(&mut self, this: Resource<TcpSocket>) -> SocketResult<bool> {
        HostTcpSocket::keep_alive_enabled(&mut self.sockets, this)
    }

    fn set_keep_alive_enabled(
        &mut self,
        this: Resource<TcpSocket>,
        value: bool,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_enabled(&mut self.sockets, this, value)
    }

    fn keep_alive_idle_time(&mut self, this: Resource<TcpSocket>) -> SocketResult<u64> {
        HostTcpSocket::keep_alive_idle_time(&mut self.sockets, this)
    }

    fn set_keep_alive_idle_time(
        &mut self,
        this: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_idle_time(&mut self.sockets, this, value)
    }

    fn keep_alive_interval(&mut self, this: Resource<TcpSocket>) -> SocketResult<u64> {
        HostTcpSocket::keep_alive_interval(&mut self.sockets, this)
    }

    fn set_keep_alive_interval(
        &mut self,
        this: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_interval(&mut self.sockets, this, value)
    }

    fn keep_alive_count(&mut self, this: Resource<TcpSocket>) -> SocketResult<u32> {
        HostTcpSocket::keep_alive_count(&mut self.sockets, this)
    }

    fn set_keep_alive_count(&mut self, this: Resource<TcpSocket>, value: u32) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_count(&mut self.sockets, this, value)
    }

    fn hop_limit(&mut self, this: Resource<TcpSocket>) -> SocketResult<u8> {
        HostTcpSocket::hop_limit(&mut self.sockets, this)
    }

    fn set_hop_limit(&mut self, this: Resource<TcpSocket>, value: u8) -> SocketResult<()> {
        HostTcpSocket::set_hop_limit(&mut self.sockets, this, value)
    }

    fn receive_buffer_size(&mut self, this: Resource<TcpSocket>) -> SocketResult<u64> {
        HostTcpSocket::receive_buffer_size(&mut self.sockets, this)
    }

    fn set_receive_buffer_size(
        &mut self,
        this: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_receive_buffer_size(&mut self.sockets, this, value)
    }

    fn send_buffer_size(&mut self, this: Resource<TcpSocket>) -> SocketResult<u64> {
        HostTcpSocket::send_buffer_size(&mut self.sockets, this)
    }

    fn set_send_buffer_size(&mut self, this: Resource<TcpSocket>, value: u64) -> SocketResult<()> {
        HostTcpSocket::set_send_buffer_size(&mut self.sockets, this, value)
    }

    fn subscribe(&mut self, this: Resource<TcpSocket>) -> wasmtime::Result<Resource<DynPollable>> {
        let ready = match self.virt.p2_tunnels.get(&this.rep()) {
            Some(P2Tunnel::Connecting { ready, .. }) => ready.clone(),
            Some(P2Tunnel::Connected(c)) => c.ready.clone(),
            Some(P2Tunnel::Failed) => {
                let (tx, rx) = watch::channel(true);
                drop(tx);
                rx
            }
            None => return HostTcpSocket::subscribe(&mut self.sockets, this),
        };
        let entry = self.sockets.table.push(TunnelReady(ready))?;
        subscribe(self.sockets.table, entry)
    }

    fn shutdown(
        &mut self,
        this: Resource<TcpSocket>,
        shutdown_type: ShutdownType,
    ) -> SocketResult<()> {
        let Some(tunnel) = self.virt.p2_tunnels.get(&this.rep()) else {
            return HostTcpSocket::shutdown(&mut self.sockets, this, shutdown_type);
        };
        let P2Tunnel::Connected(c) = tunnel else {
            return Err(ErrorCode::InvalidState.into());
        };
        match shutdown_type {
            ShutdownType::Send => request_shutdown(&c.write),
            ShutdownType::Receive => close_read(&c.read),
            ShutdownType::Both => {
                request_shutdown(&c.write);
                close_read(&c.read);
            }
        }
        Ok(())
    }

    fn drop(&mut self, this: Resource<TcpSocket>) -> wasmtime::Result<()> {
        self.virt.p2_tunnels.remove(&this.rep());
        self.virt.tunnels.remove(&this.rep());
        HostTcpSocket::drop(&mut self.sockets, this)
    }
}

// --- sockets/ip-name-lookup ---

impl LookupHost for VirtView<'_> {
    fn resolve_addresses(
        &mut self,
        network: Resource<Network>,
        name: String,
    ) -> SocketResult<Resource<ResolveAddressStream>> {
        match tls_virt_common::strip_suffix(&name) {
            Some(real) => {
                // Delegate the inner resolution (policy included) and
                // drain it through the wrapped resource.
                let inner =
                    LookupHost::resolve_addresses(&mut self.sockets, network, real.to_string())?;
                self.virt.p2_resolves.insert(
                    inner.rep(),
                    P2Resolve::Draining {
                        hostname: real.to_string(),
                        addrs: Vec::new(),
                    },
                );
                Ok(inner)
            }
            None => LookupHost::resolve_addresses(&mut self.sockets, network, name),
        }
    }
}

impl HostResolveAddressStream for VirtView<'_> {
    fn resolve_next_address(
        &mut self,
        resource: Resource<ResolveAddressStream>,
    ) -> SocketResult<Option<IpAddress>> {
        let rep = resource.rep();
        if !self.virt.p2_resolves.contains_key(&rep) {
            return HostResolveAddressStream::resolve_next_address(&mut self.sockets, resource);
        }
        loop {
            let next = HostResolveAddressStream::resolve_next_address(
                &mut self.sockets,
                Resource::new_borrow(rep),
            )?;
            let Some(state) = self.virt.p2_resolves.get_mut(&rep) else {
                return Ok(next);
            };
            match state {
                P2Resolve::Draining { hostname, addrs } => match next {
                    Some(addr) => addrs.push(ip_to_std(addr)),
                    None => {
                        if addrs.is_empty() {
                            *state = P2Resolve::Yielded;
                            return Err(ErrorCode::NameUnresolvable.into());
                        }
                        let entry = Entry {
                            hostname: std::mem::take(hostname),
                            addrs: std::mem::take(addrs),
                        };
                        *state = P2Resolve::Yielded;
                        let handle = self.virt.names.mint(entry);
                        return Ok(Some(handle_to_ip(handle)));
                    }
                },
                P2Resolve::Yielded => return Ok(None),
            }
        }
    }

    fn subscribe(
        &mut self,
        resource: Resource<ResolveAddressStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        // Readiness of the wrapped stream is exactly the delegated
        // stream's readiness.
        HostResolveAddressStream::subscribe(&mut self.sockets, resource)
    }

    fn drop(&mut self, resource: Resource<ResolveAddressStream>) -> wasmtime::Result<()> {
        self.virt.p2_resolves.remove(&resource.rep());
        HostResolveAddressStream::drop(&mut self.sockets, resource)
    }
}
