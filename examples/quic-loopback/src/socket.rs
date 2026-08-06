//! A bound `wasi:sockets` UDP socket with batched datagram streams.
//!
//! `wasi:sockets` offers no GSO/GRO or `sendmmsg` beyond the list-based
//! batching, and none is assumed.

use std::fmt;
use std::net::SocketAddr;

use wasi::io::poll::Pollable;
use wasi::sockets::instance_network::instance_network;
use wasi::sockets::network::ErrorCode;
use wasi::sockets::udp::{
    IncomingDatagramStream, OutgoingDatagram, OutgoingDatagramStream, UdpSocket as WasiUdpSocket,
};
use wasi::sockets::udp_create_socket::create_udp_socket;

use crate::addr::{family, from_wasi, to_wasi};

/// A `wasi:sockets` error.
#[derive(Debug)]
pub struct SocketError(pub ErrorCode);

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wasi:sockets error: {:?}", self.0)
    }
}

impl std::error::Error for SocketError {}

impl From<ErrorCode> for SocketError {
    fn from(code: ErrorCode) -> Self {
        Self(code)
    }
}

/// A bound UDP socket and its datagram streams.
///
/// The streams are unconnected (`stream(None)`): one socket serves any
/// number of peers, as a QUIC endpoint requires.
pub struct UdpSocket {
    // Drop order matters: the streams are child resources of the socket
    // and must be dropped before it, or resource teardown traps.
    incoming: IncomingDatagramStream,
    outgoing: OutgoingDatagramStream,
    _socket: WasiUdpSocket,
    local: SocketAddr,
}

impl UdpSocket {
    /// Creates a socket and binds it to `addr` (port 0 for ephemeral).
    pub fn bind(addr: SocketAddr) -> Result<Self, SocketError> {
        let network = instance_network();
        let socket = create_udp_socket(family(addr))?;
        socket.start_bind(&network, to_wasi(addr))?;
        loop {
            match socket.finish_bind() {
                Ok(()) => break,
                Err(ErrorCode::WouldBlock) => socket.subscribe().block(),
                Err(e) => return Err(e.into()),
            }
        }
        let (incoming, outgoing) = socket.stream(None)?;
        let local = from_wasi(socket.local_address()?);
        Ok(Self {
            _socket: socket,
            incoming,
            outgoing,
            local,
        })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Receives up to `max` datagrams. Non-blocking: an empty vector means
    /// nothing is queued.
    pub fn receive(&self, max: u64) -> Result<Vec<(Vec<u8>, SocketAddr)>, SocketError> {
        let datagrams = self.incoming.receive(max)?;
        Ok(datagrams
            .into_iter()
            .map(|d| (d.data, from_wasi(d.remote_address)))
            .collect())
    }

    /// Sends as many of `datagrams` as the stream currently permits,
    /// returning how many were accepted.
    pub fn send(&self, datagrams: &[(Vec<u8>, SocketAddr)]) -> Result<usize, SocketError> {
        let permitted = self.outgoing.check_send()? as usize;
        if permitted == 0 {
            return Ok(0);
        }
        let batch: Vec<OutgoingDatagram> = datagrams
            .iter()
            .take(permitted)
            .map(|(data, remote)| OutgoingDatagram {
                data: data.clone(),
                remote_address: Some(to_wasi(*remote)),
            })
            .collect();
        Ok(self.outgoing.send(&batch)? as usize)
    }

    /// A pollable that resolves when a datagram is ready to receive.
    pub fn incoming_pollable(&self) -> Pollable {
        self.incoming.subscribe()
    }

    /// A pollable that resolves when the stream can accept more datagrams.
    pub fn outgoing_pollable(&self) -> Pollable {
        self.outgoing.subscribe()
    }
}
