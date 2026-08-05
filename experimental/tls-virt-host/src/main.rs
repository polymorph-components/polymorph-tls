//! Experimental wasmtime embedding: transparent TLS as a `wasi:sockets`
//! host provider.
//!
//! The host-side counterpart of the `tls-virt` component virtualizer:
//! the same interposition — suffix-opted name resolutions return minted
//! handle addresses, connects to handle addresses open a real TCP
//! connection and drive a TLS 1.3 handshake (SNI + verification against
//! baked fixture roots), and the guest's bytes tunnel through TLS it
//! cannot observe — implemented by wrapping wasmtime-wasi's
//! `wasi:sockets@0.3.0` implementation instead of composing a wasm
//! component in front of it.
//!
//! The provider implements wasmtime-wasi's generated sockets host
//! traits with its own store projection. Every operation on a
//! non-tunnel socket delegates to wasmtime-wasi's implementations of
//! the same traits (public impls on `WasiSocketsCtxView` and
//! `WasiSockets`), so passthrough behavior — including `listen` and its
//! accepted sockets — is wasmtime-wasi's own, permission checks
//! included. Tunnels are keyed off the socket's table index in a side
//! map; their data path is native (tokio + rustls over the `lann-tls`
//! profile configs) and never touches a wasmtime-wasi socket.
//!
//! ```text
//! tls-virt-host <component.wasm> [guest args...]
//! ```
//!
//! Runs the component's `wasi:cli/run@0.3.0` export with stdio
//! inherited, network inherited, and name lookup allowed. Prototype
//! limits are recorded in README.md.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use wasmtime::component::{
    Access, Accessor, Component, Destination, FutureReader, HasData, Linker, Resource,
    ResourceTable, Source, StreamConsumer, StreamProducer, StreamReader, StreamResult,
};
use wasmtime::error::Context as _;
use wasmtime::{bail, Result};
use wasmtime::{AsContextMut as _, Config, Engine, Store, StoreContextMut};
use wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::{self, ErrorCode as LookupErrorCode};
use wasmtime_wasi::p3::bindings::sockets::types::{
    self, Duration, ErrorCode, HostTcpSocket, HostTcpSocketWithStore, HostUdpSocket,
    HostUdpSocketWithStore, IpAddress, IpAddressFamily, IpSocketAddress, TcpSocket, UdpSocket,
};
use wasmtime_wasi::p3::bindings::Command;
use wasmtime_wasi::p3::sockets::{SocketError, SocketResult};
use wasmtime_wasi::sockets::{WasiSockets, WasiSocketsCtxView};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Names under this suffix opt in to TLS tunneling.
const SUFFIX: &str = ".tls-virt.alt";

/// Trust anchor for tunneled connections (prototype: the repository's
/// test CA).
const ROOT: &[u8] = include_bytes!("../../../rust/quinn/tests/testdata/ca.der");

/// Read hop size for the tunnel's receive producer.
const CHUNK: usize = 16 * 1024;

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
type TlsReadHalf = tokio::io::ReadHalf<TlsStream>;
type TlsWriteHalf = tokio::io::WriteHalf<TlsStream>;

// --- store data and projections ---

struct Ctx {
    wasi: WasiCtx,
    table: ResourceTable,
    virt: VirtCtx,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// The virtualizing provider's own state.
struct VirtCtx {
    /// The random ULA /64 this instance mints handles under.
    prefix: [u8; 8],
    /// Handle table: random 64-bit suffix → resolved destination.
    names: HashMap<u64, Entry>,
    /// Tunnels, keyed by the socket resource's table index. A socket
    /// with an entry here is a tunnel; every other socket delegates.
    tunnels: HashMap<u32, Tunnel>,
    /// TLS 1.3 client configuration: the `lann-tls` profile configs
    /// over the baked fixture root.
    connector: TlsConnector,
    /// Runtime handle for the close_notify shutdown task (spawned from
    /// a `Drop` impl, which cannot await).
    runtime: tokio::runtime::Handle,
}

struct Entry {
    hostname: String,
    addrs: Vec<IpAddress>,
}

struct Tunnel {
    /// The handle address the guest dialed, for `get-remote-address`.
    remote: IpSocketAddress,
    /// The real connection's local address.
    local: Option<SocketAddr>,
    /// Taken by `receive`.
    read: Option<TlsReadHalf>,
    /// Taken by `send`.
    write: Option<TlsWriteHalf>,
}

impl VirtCtx {
    fn new() -> Result<Self> {
        let mut prefix = [0u8; 8];
        getrandom::fill(&mut prefix).context("randomness unavailable")?;
        prefix[0] = 0xfd;

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ROOT.to_vec()))
            .context("invalid baked root certificate")?;
        let config = lann_tls::client_config(roots);

        Ok(Self {
            prefix,
            names: HashMap::new(),
            tunnels: HashMap::new(),
            connector: TlsConnector::from(Arc::new(config)),
            runtime: tokio::runtime::Handle::current(),
        })
    }

    fn mint_handle(&mut self, entry: Entry) -> IpAddress {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).expect("randomness available");
        let key = u64::from_be_bytes(suffix);
        self.names.insert(key, entry);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.prefix);
        bytes[8..].copy_from_slice(&suffix);
        let seg = |i: usize| u16::from_be_bytes([bytes[2 * i], bytes[2 * i + 1]]);
        IpAddress::Ipv6((
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
    fn lookup_handle(&self, remote: &IpSocketAddress) -> Option<(String, Vec<IpAddress>, u16)> {
        let IpSocketAddress::Ipv6(v6) = remote else {
            return None;
        };
        let (a, b, c, d, e, f, g, h) = v6.address;
        let mut bytes = [0u8; 16];
        for (i, seg) in [a, b, c, d, e, f, g, h].into_iter().enumerate() {
            bytes[2 * i..2 * i + 2].copy_from_slice(&seg.to_be_bytes());
        }
        if bytes[..8] != self.prefix {
            return None;
        }
        let key = u64::from_be_bytes(bytes[8..].try_into().unwrap());
        self.names
            .get(&key)
            .map(|e| (e.hostname.clone(), e.addrs.clone(), v6.port))
    }
}

/// The provider's store projection: its own state plus wasmtime-wasi's
/// sockets view for delegation.
struct VirtView<'a> {
    virt: &'a mut VirtCtx,
    sockets: WasiSocketsCtxView<'a>,
}

/// `HasData` marker for the provider (the `D` in the generated
/// `add_to_linker` and `*WithStore` traits).
struct VirtSockets;

impl HasData for VirtSockets {
    type Data<'a> = VirtView<'a>;
}

/// Store projection for the provider's own traits.
fn virt_view(ctx: &mut Ctx) -> VirtView<'_> {
    VirtView {
        virt: &mut ctx.virt,
        sockets: WasiSocketsCtxView {
            ctx: ctx.wasi.sockets(),
            table: &mut ctx.table,
        },
    }
}

/// Store projection for delegation to wasmtime-wasi's own impls.
fn wasi_sockets_view(ctx: &mut Ctx) -> WasiSocketsCtxView<'_> {
    WasiSocketsCtxView {
        ctx: ctx.wasi.sockets(),
        table: &mut ctx.table,
    }
}

// --- the wrapped sockets provider ---

impl types::Host for VirtView<'_> {
    fn convert_error_code(&mut self, err: SocketError) -> wasmtime::Result<ErrorCode> {
        types::Host::convert_error_code(&mut self.sockets, err)
    }
}

impl HostTcpSocket for VirtView<'_> {
    fn create(&mut self, address_family: IpAddressFamily) -> SocketResult<Resource<TcpSocket>> {
        HostTcpSocket::create(&mut self.sockets, address_family)
    }

    async fn bind(
        &mut self,
        socket: Resource<TcpSocket>,
        local_address: IpSocketAddress,
    ) -> SocketResult<()> {
        HostTcpSocket::bind(&mut self.sockets, socket, local_address).await
    }

    fn get_local_address(&mut self, socket: Resource<TcpSocket>) -> SocketResult<IpSocketAddress> {
        if let Some(tunnel) = self.virt.tunnels.get(&socket.rep()) {
            return match tunnel.local {
                Some(addr) => Ok(addr.into()),
                None => Err(ErrorCode::InvalidState.into()),
            };
        }
        HostTcpSocket::get_local_address(&mut self.sockets, socket)
    }

    fn get_remote_address(&mut self, socket: Resource<TcpSocket>) -> SocketResult<IpSocketAddress> {
        // Preserve the illusion: the guest dialed the handle.
        if let Some(tunnel) = self.virt.tunnels.get(&socket.rep()) {
            return Ok(tunnel.remote);
        }
        HostTcpSocket::get_remote_address(&mut self.sockets, socket)
    }

    fn get_is_listening(&mut self, socket: Resource<TcpSocket>) -> wasmtime::Result<bool> {
        HostTcpSocket::get_is_listening(&mut self.sockets, socket)
    }

    fn get_address_family(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> wasmtime::Result<IpAddressFamily> {
        HostTcpSocket::get_address_family(&mut self.sockets, socket)
    }

    fn set_listen_backlog_size(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_listen_backlog_size(&mut self.sockets, socket, value)
    }

    fn get_keep_alive_enabled(&mut self, socket: Resource<TcpSocket>) -> SocketResult<bool> {
        HostTcpSocket::get_keep_alive_enabled(&mut self.sockets, socket)
    }

    fn set_keep_alive_enabled(
        &mut self,
        socket: Resource<TcpSocket>,
        value: bool,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_enabled(&mut self.sockets, socket, value)
    }

    fn get_keep_alive_idle_time(&mut self, socket: Resource<TcpSocket>) -> SocketResult<Duration> {
        HostTcpSocket::get_keep_alive_idle_time(&mut self.sockets, socket)
    }

    fn set_keep_alive_idle_time(
        &mut self,
        socket: Resource<TcpSocket>,
        value: Duration,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_idle_time(&mut self.sockets, socket, value)
    }

    fn get_keep_alive_interval(&mut self, socket: Resource<TcpSocket>) -> SocketResult<Duration> {
        HostTcpSocket::get_keep_alive_interval(&mut self.sockets, socket)
    }

    fn set_keep_alive_interval(
        &mut self,
        socket: Resource<TcpSocket>,
        value: Duration,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_interval(&mut self.sockets, socket, value)
    }

    fn get_keep_alive_count(&mut self, socket: Resource<TcpSocket>) -> SocketResult<u32> {
        HostTcpSocket::get_keep_alive_count(&mut self.sockets, socket)
    }

    fn set_keep_alive_count(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u32,
    ) -> SocketResult<()> {
        HostTcpSocket::set_keep_alive_count(&mut self.sockets, socket, value)
    }

    fn get_hop_limit(&mut self, socket: Resource<TcpSocket>) -> SocketResult<u8> {
        HostTcpSocket::get_hop_limit(&mut self.sockets, socket)
    }

    fn set_hop_limit(&mut self, socket: Resource<TcpSocket>, value: u8) -> SocketResult<()> {
        HostTcpSocket::set_hop_limit(&mut self.sockets, socket, value)
    }

    fn get_receive_buffer_size(&mut self, socket: Resource<TcpSocket>) -> SocketResult<u64> {
        HostTcpSocket::get_receive_buffer_size(&mut self.sockets, socket)
    }

    fn set_receive_buffer_size(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_receive_buffer_size(&mut self.sockets, socket, value)
    }

    fn get_send_buffer_size(&mut self, socket: Resource<TcpSocket>) -> SocketResult<u64> {
        HostTcpSocket::get_send_buffer_size(&mut self.sockets, socket)
    }

    fn set_send_buffer_size(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostTcpSocket::set_send_buffer_size(&mut self.sockets, socket, value)
    }

    fn drop(&mut self, socket: Resource<TcpSocket>) -> wasmtime::Result<()> {
        self.virt.tunnels.remove(&socket.rep());
        HostTcpSocket::drop(&mut self.sockets, socket)
    }
}

impl HostTcpSocketWithStore<Ctx> for VirtSockets {
    async fn connect(
        accessor: &Accessor<Ctx, Self>,
        socket: Resource<TcpSocket>,
        remote_address: IpSocketAddress,
    ) -> SocketResult<()> {
        let entry = accessor.with(|mut a| a.get().virt.lookup_handle(&remote_address));
        let Some((hostname, addrs, port)) = entry else {
            // Pass-through: wasmtime-wasi's connect, permission check
            // included.
            let delegated = accessor.with_getter::<WasiSockets>(wasi_sockets_view);
            return <WasiSockets as HostTcpSocketWithStore<Ctx>>::connect(
                &delegated,
                socket,
                remote_address,
            )
            .await;
        };

        // Tunnel path: real transport plus TLS handshake, all native.
        // The guest's socket resource stays in its unconnected state and
        // serves only as the handle the tunnel is keyed under.
        let addr = pick_addr(&addrs, port).ok_or(ErrorCode::RemoteUnreachable)?;
        let connector = accessor.with(|mut a| a.get().virt.connector.clone());

        let stream = TcpStream::connect(addr).await.map_err(ErrorCode::from)?;
        let local = stream.local_addr().ok();
        let server_name =
            ServerName::try_from(hostname.clone()).map_err(|_| ErrorCode::InvalidArgument)?;
        let tls = connector.connect(server_name, stream).await.map_err(|e| {
            eprintln!("tls-virt-host: TLS handshake with {hostname:?} failed: {e}");
            ErrorCode::ConnectionReset
        })?;
        let (read, write) = tokio::io::split(tls);

        accessor.with(|mut a| {
            a.get().virt.tunnels.insert(
                socket.rep(),
                Tunnel {
                    remote: remote_address,
                    local,
                    read: Some(read),
                    write: Some(write),
                },
            )
        });
        Ok(())
    }

    async fn listen(
        mut store: Access<'_, Ctx, Self>,
        socket: Resource<TcpSocket>,
    ) -> SocketResult<StreamReader<Resource<TcpSocket>>> {
        // Pure delegation: accepted sockets land in the shared resource
        // table as ordinary wasmtime-wasi sockets, so every operation on
        // them delegates too.
        let store = Access::<Ctx, WasiSockets>::new(store.as_context_mut(), wasi_sockets_view);
        <WasiSockets as HostTcpSocketWithStore<Ctx>>::listen(store, socket).await
    }

    fn send(
        mut store: Access<'_, Ctx, Self>,
        socket: Resource<TcpSocket>,
        mut data: StreamReader<u8>,
    ) -> wasmtime::Result<FutureReader<Result<(), ErrorCode>>> {
        let taken = {
            let view = store.get();
            let runtime = view.virt.runtime.clone();
            view.virt
                .tunnels
                .get_mut(&socket.rep())
                .map(|t| (t.write.take(), runtime))
        };
        match taken {
            Some((Some(write), runtime)) => {
                let (result_tx, result_rx) = oneshot::channel();
                data.pipe(
                    &mut store,
                    TlsSendConsumer {
                        write: Some(write),
                        result: Some(result_tx),
                        runtime,
                    },
                )?;
                FutureReader::new(&mut store, result_rx)
            }
            Some((None, _)) => {
                data.close(&mut store)?;
                FutureReader::new(&mut store, async {
                    Ok::<_, wasmtime::Error>(Err(ErrorCode::InvalidState))
                })
            }
            None => {
                let store =
                    Access::<Ctx, WasiSockets>::new(store.as_context_mut(), wasi_sockets_view);
                <WasiSockets as HostTcpSocketWithStore<Ctx>>::send(store, socket, data)
            }
        }
    }

    fn receive(
        mut store: Access<'_, Ctx, Self>,
        socket: Resource<TcpSocket>,
    ) -> wasmtime::Result<(StreamReader<u8>, FutureReader<Result<(), ErrorCode>>)> {
        let taken = store
            .get()
            .virt
            .tunnels
            .get_mut(&socket.rep())
            .map(|t| t.read.take());
        match taken {
            Some(Some(read)) => {
                let (result_tx, result_rx) = oneshot::channel();
                Ok((
                    StreamReader::new(
                        &mut store,
                        TlsReceiveProducer {
                            read,
                            result: Some(result_tx),
                        },
                    )?,
                    FutureReader::new(&mut store, result_rx)?,
                ))
            }
            Some(None) => Ok((
                StreamReader::new(&mut store, std::iter::empty())?,
                FutureReader::new(&mut store, async {
                    Ok::<_, wasmtime::Error>(Err(ErrorCode::InvalidState))
                })?,
            )),
            None => {
                let store =
                    Access::<Ctx, WasiSockets>::new(store.as_context_mut(), wasi_sockets_view);
                <WasiSockets as HostTcpSocketWithStore<Ctx>>::receive(store, socket)
            }
        }
    }
}

// --- UDP: pure delegation ---

impl HostUdpSocket for VirtView<'_> {
    fn create(&mut self, address_family: IpAddressFamily) -> SocketResult<Resource<UdpSocket>> {
        HostUdpSocket::create(&mut self.sockets, address_family)
    }

    async fn bind(
        &mut self,
        socket: Resource<UdpSocket>,
        local_address: IpSocketAddress,
    ) -> SocketResult<()> {
        HostUdpSocket::bind(&mut self.sockets, socket, local_address).await
    }

    async fn connect(
        &mut self,
        socket: Resource<UdpSocket>,
        remote_address: IpSocketAddress,
    ) -> SocketResult<()> {
        HostUdpSocket::connect(&mut self.sockets, socket, remote_address).await
    }

    fn disconnect(&mut self, socket: Resource<UdpSocket>) -> SocketResult<()> {
        HostUdpSocket::disconnect(&mut self.sockets, socket)
    }

    fn get_local_address(&mut self, socket: Resource<UdpSocket>) -> SocketResult<IpSocketAddress> {
        HostUdpSocket::get_local_address(&mut self.sockets, socket)
    }

    fn get_remote_address(&mut self, socket: Resource<UdpSocket>) -> SocketResult<IpSocketAddress> {
        HostUdpSocket::get_remote_address(&mut self.sockets, socket)
    }

    fn get_address_family(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> wasmtime::Result<IpAddressFamily> {
        HostUdpSocket::get_address_family(&mut self.sockets, socket)
    }

    fn get_unicast_hop_limit(&mut self, socket: Resource<UdpSocket>) -> SocketResult<u8> {
        HostUdpSocket::get_unicast_hop_limit(&mut self.sockets, socket)
    }

    fn set_unicast_hop_limit(
        &mut self,
        socket: Resource<UdpSocket>,
        value: u8,
    ) -> SocketResult<()> {
        HostUdpSocket::set_unicast_hop_limit(&mut self.sockets, socket, value)
    }

    fn get_receive_buffer_size(&mut self, socket: Resource<UdpSocket>) -> SocketResult<u64> {
        HostUdpSocket::get_receive_buffer_size(&mut self.sockets, socket)
    }

    fn set_receive_buffer_size(
        &mut self,
        socket: Resource<UdpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostUdpSocket::set_receive_buffer_size(&mut self.sockets, socket, value)
    }

    fn get_send_buffer_size(&mut self, socket: Resource<UdpSocket>) -> SocketResult<u64> {
        HostUdpSocket::get_send_buffer_size(&mut self.sockets, socket)
    }

    fn set_send_buffer_size(
        &mut self,
        socket: Resource<UdpSocket>,
        value: u64,
    ) -> SocketResult<()> {
        HostUdpSocket::set_send_buffer_size(&mut self.sockets, socket, value)
    }

    fn drop(&mut self, socket: Resource<UdpSocket>) -> wasmtime::Result<()> {
        HostUdpSocket::drop(&mut self.sockets, socket)
    }
}

impl HostUdpSocketWithStore<Ctx> for VirtSockets {
    async fn send(
        accessor: &Accessor<Ctx, Self>,
        socket: Resource<UdpSocket>,
        data: Vec<u8>,
        remote_address: Option<IpSocketAddress>,
    ) -> SocketResult<()> {
        let delegated = accessor.with_getter::<WasiSockets>(wasi_sockets_view);
        <WasiSockets as HostUdpSocketWithStore<Ctx>>::send(&delegated, socket, data, remote_address)
            .await
    }

    async fn receive(
        accessor: &Accessor<Ctx, Self>,
        socket: Resource<UdpSocket>,
    ) -> SocketResult<(Vec<u8>, IpSocketAddress)> {
        let delegated = accessor.with_getter::<WasiSockets>(wasi_sockets_view);
        <WasiSockets as HostUdpSocketWithStore<Ctx>>::receive(&delegated, socket).await
    }
}

// --- name lookup: the opt-in seam ---

impl ip_name_lookup::Host for VirtView<'_> {}

impl ip_name_lookup::HostWithStore<Ctx> for VirtSockets {
    async fn resolve_addresses(
        accessor: &Accessor<Ctx, Self>,
        name: String,
    ) -> wasmtime::Result<Result<Vec<IpAddress>, LookupErrorCode>> {
        let delegated = accessor.with_getter::<WasiSockets>(wasi_sockets_view);
        match name.strip_suffix(SUFFIX) {
            Some(real) => {
                // The inner resolution is wasmtime-wasi's, so the
                // allow-ip-name-lookup policy applies to opted-in names
                // too.
                let addrs =
                    match <WasiSockets as ip_name_lookup::HostWithStore<Ctx>>::resolve_addresses(
                        &delegated,
                        real.to_string(),
                    )
                    .await?
                    {
                        Ok(addrs) => addrs,
                        Err(err) => return Ok(Err(err)),
                    };
                if addrs.is_empty() {
                    return Ok(Err(LookupErrorCode::NameUnresolvable));
                }
                let handle = accessor.with(|mut a| {
                    a.get().virt.mint_handle(Entry {
                        hostname: real.to_string(),
                        addrs,
                    })
                });
                Ok(Ok(vec![handle]))
            }
            None => {
                <WasiSockets as ip_name_lookup::HostWithStore<Ctx>>::resolve_addresses(
                    &delegated, name,
                )
                .await
            }
        }
    }
}

/// A destination socket-address from a resolved entry, preferring IPv6.
fn pick_addr(addrs: &[IpAddress], port: u16) -> Option<SocketAddr> {
    let v6 = addrs.iter().find_map(|a| match a {
        IpAddress::Ipv6(s) => Some(SocketAddr::from((
            std::net::Ipv6Addr::new(s.0, s.1, s.2, s.3, s.4, s.5, s.6, s.7),
            port,
        ))),
        _ => None,
    });
    v6.or_else(|| {
        addrs.iter().find_map(|a| match a {
            IpAddress::Ipv4((a, b, c, d)) => Some(SocketAddr::from((
                std::net::Ipv4Addr::new(*a, *b, *c, *d),
                port,
            ))),
            _ => None,
        })
    })
}

// --- the tunnel data path ---

/// Consumes the guest's transmit stream into the TLS write half. On
/// drop (the guest's stream ended), a spawned task drives the TLS
/// shutdown — close_notify, then FIN — and then resolves the verdict.
struct TlsSendConsumer {
    write: Option<TlsWriteHalf>,
    result: Option<oneshot::Sender<Result<(), ErrorCode>>>,
    runtime: tokio::runtime::Handle,
}

impl TlsSendConsumer {
    fn close(&mut self, res: Result<(), ErrorCode>) {
        let Some(tx) = self.result.take() else {
            return;
        };
        match (res, self.write.take()) {
            (Ok(()), Some(mut write)) => {
                self.runtime.spawn(async move {
                    let res = write.shutdown().await.map_err(|e| {
                        eprintln!("tls-virt-host: TLS shutdown failed: {e}");
                        ErrorCode::from(e)
                    });
                    _ = tx.send(res);
                });
            }
            (res, write) => {
                // Error path: no clean close is possible; dropping the
                // write half closes the transport without close_notify.
                drop(write);
                _ = tx.send(res);
            }
        }
    }
}

impl Drop for TlsSendConsumer {
    fn drop(&mut self) {
        self.close(Ok(()));
    }
}

impl<D> StreamConsumer<D> for TlsSendConsumer {
    type Item = u8;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        store: StoreContextMut<D>,
        src: Source<Self::Item>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = &mut *self;
        let Some(write) = this.write.as_mut() else {
            return Poll::Ready(Ok(StreamResult::Dropped));
        };
        let mut src = src.as_direct(store);
        let buf = src.remaining();
        if buf.is_empty() {
            // Zero-length write: a readiness probe. No probe exists for
            // a TLS half; claim readiness.
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        match Pin::new(write).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                src.mark_read(n);
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(Err(e)) => {
                eprintln!("tls-virt-host: send direction failed: {e}");
                this.close(Err(ErrorCode::from(e)));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Produces the guest's receive stream from the TLS read half. A clean
/// TLS end (close_notify) resolves the verdict `ok`; a transport close
/// without close_notify resolves it `err(connection-reset)`, never
/// end-of-data.
struct TlsReceiveProducer {
    read: TlsReadHalf,
    result: Option<oneshot::Sender<Result<(), ErrorCode>>>,
}

impl TlsReceiveProducer {
    fn close(&mut self, res: Result<(), ErrorCode>) {
        if let Some(tx) = self.result.take() {
            _ = tx.send(res);
        }
    }
}

impl<D> StreamProducer<D> for TlsReceiveProducer {
    type Item = u8;
    type Buffer = BytesMut;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<'a, D>,
        dst: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = &mut *self;
        if dst.remaining(store.as_context_mut()) == Some(0) {
            // Zero-length read: a readiness probe. No probe exists for a
            // TLS half; claim readiness.
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let mut dst = dst.as_direct(store, CHUNK);
        let mut buf = ReadBuf::new(dst.remaining());
        match Pin::new(&mut this.read).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len();
                if n == 0 {
                    // Clean TLS end: the peer sent close_notify.
                    this.close(Ok(()));
                    Poll::Ready(Ok(StreamResult::Dropped))
                } else {
                    dst.mark_written(n);
                    Poll::Ready(Ok(StreamResult::Completed))
                }
            }
            Poll::Ready(Err(e)) => {
                eprintln!("tls-virt-host: receive direction failed: {e}");
                this.close(Err(ErrorCode::ConnectionReset));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// --- driver ---

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, component_path, _guest_args @ ..] = args.as_slice() else {
        bail!(
            "usage: {} <component.wasm> [guest args...]",
            args.first().map(String::as_str).unwrap_or("tls-virt-host"),
        );
    };

    let mut config = Config::new();
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;
    let component =
        Component::from_file(&engine, component_path).context("failed to load component")?;

    let mut linker = Linker::<Ctx>::new(&engine);
    // The 0.2.x baseline (the guest std's imports). Note this includes
    // wasmtime-wasi's p2 sockets unwrapped; see README.md.
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    // The p3 interfaces: everything stock except sockets, which is ours.
    wasmtime_wasi::p3::cli::add_to_linker(&mut linker)?;
    wasmtime_wasi::p3::clocks::add_to_linker(&mut linker)?;
    wasmtime_wasi::p3::filesystem::add_to_linker(&mut linker)?;
    wasmtime_wasi::p3::random::add_to_linker(&mut linker)?;
    types::add_to_linker::<Ctx, VirtSockets>(&mut linker, virt_view)?;
    ip_name_lookup::add_to_linker::<Ctx, VirtSockets>(&mut linker, virt_view)?;

    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdio()
        .args(&args[1..])
        .inherit_network()
        .allow_ip_name_lookup(true);

    let mut store = Store::new(
        &engine,
        Ctx {
            wasi: wasi.build(),
            table: ResourceTable::new(),
            virt: VirtCtx::new()?,
        },
    );
    let command = Command::instantiate_async(&mut store, &component, &linker)
        .await
        .context("failed to instantiate `wasi:cli/command`")?;
    let result = store
        .run_concurrent(async move |store| command.wasi_cli_run().call_run(store).await)
        .await
        .context("failed to run the component")?
        .context("guest trapped")?;
    if result.is_err() {
        std::process::exit(1);
    }
    Ok(())
}
