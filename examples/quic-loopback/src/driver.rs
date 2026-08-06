//! Pumps a `quinn_proto::Endpoint` and its connections over one socket.
//!
//! quinn-proto is sans-IO: it consumes received datagrams and emits
//! datagrams-to-send plus timer deadlines. The driver is the I/O half:
//! batched receive and transmit on the socket, due timers fired in
//! [`Driver::pump`], and pollables plus [`Driver::next_deadline`] for
//! the caller's poll set.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use bytes::BytesMut;
use quinn_proto::{
    ClientConfig, ConnectError, Connection, ConnectionEvent, ConnectionHandle, DatagramEvent,
    Endpoint, Event,
};
use wasi::io::poll::Pollable;

use crate::socket::{SocketError, UdpSocket};

/// How many datagrams one receive call asks for.
const RECEIVE_BATCH: u64 = 64;

/// Drives one QUIC endpoint over one UDP socket.
///
/// The driver is synchronous and single-threaded, in keeping with the
/// component model's execution model: [`pump`](Self::pump) makes all
/// progress that is possible without blocking; between pumps the caller
/// blocks on a poll set built from the socket pollables and
/// [`next_deadline`](Self::next_deadline), then drains
/// [`poll_event`](Self::poll_event) for connection events.
pub struct Driver {
    socket: UdpSocket,
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, Connection>,
    events: VecDeque<(ConnectionHandle, Event)>,
    outbound: VecDeque<(Vec<u8>, SocketAddr)>,
}

impl Driver {
    /// Creates a driver for `endpoint` over `socket`.
    ///
    /// For a server, construct the endpoint with a `ServerConfig`; the
    /// driver accepts every incoming connection.
    pub fn new(endpoint: Endpoint, socket: UdpSocket) -> Self {
        Self {
            socket,
            endpoint,
            connections: HashMap::new(),
            events: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    /// The socket's bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    /// Initiates a client connection.
    pub fn connect(
        &mut self,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<ConnectionHandle, ConnectError> {
        let (handle, connection) =
            self.endpoint
                .connect(Instant::now(), config, remote, server_name)?;
        self.connections.insert(handle, connection);
        Ok(handle)
    }

    /// Direct access to a connection (streams, datagrams, close).
    pub fn connection_mut(&mut self, handle: ConnectionHandle) -> Option<&mut Connection> {
        self.connections.get_mut(&handle)
    }

    /// Takes the next queued application event.
    pub fn poll_event(&mut self) -> Option<(ConnectionHandle, Event)> {
        self.events.pop_front()
    }

    /// Makes all progress currently possible without blocking: receives
    /// datagrams, fires due timers, collects transmits, and flushes the
    /// send queue. Returns `true` if anything happened.
    pub fn pump(&mut self) -> Result<bool, SocketError> {
        let mut moved = false;
        let now = Instant::now();
        let mut buf = Vec::new();

        // Receive.
        loop {
            let datagrams = self.socket.receive(RECEIVE_BATCH)?;
            if datagrams.is_empty() {
                break;
            }
            moved = true;
            for (data, remote) in datagrams {
                buf.clear();
                match self.endpoint.handle(
                    now,
                    remote,
                    None,
                    None,
                    BytesMut::from(&data[..]),
                    &mut buf,
                ) {
                    Some(DatagramEvent::NewConnection(incoming)) => {
                        buf.clear();
                        match self.endpoint.accept(incoming, now, &mut buf, None) {
                            Ok((handle, connection)) => {
                                self.connections.insert(handle, connection);
                            }
                            Err(err) => {
                                if let Some(transmit) = err.response {
                                    self.outbound.push_back((
                                        buf[..transmit.size].to_vec(),
                                        transmit.destination,
                                    ));
                                }
                            }
                        }
                    }
                    Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                        self.deliver(handle, event);
                    }
                    Some(DatagramEvent::Response(transmit)) => {
                        self.outbound
                            .push_back((buf[..transmit.size].to_vec(), transmit.destination));
                    }
                    None => {}
                }
            }
        }

        // Timers, endpoint events, transmits, application events.
        let mut endpoint_events = Vec::new();
        for (handle, connection) in self.connections.iter_mut() {
            if let Some(deadline) = connection.poll_timeout() {
                if deadline <= now {
                    connection.handle_timeout(now);
                    moved = true;
                }
            }
            while let Some(event) = connection.poll_endpoint_events() {
                endpoint_events.push((*handle, event));
            }
            loop {
                buf.clear();
                match connection.poll_transmit(now, 1, &mut buf) {
                    Some(transmit) => {
                        moved = true;
                        self.outbound
                            .push_back((buf[..transmit.size].to_vec(), transmit.destination));
                    }
                    None => break,
                }
            }
            while let Some(event) = connection.poll() {
                moved = true;
                self.events.push_back((*handle, event));
            }
        }
        for (handle, event) in endpoint_events {
            let drained = event.is_drained();
            if let Some(reply) = self.endpoint.handle_event(handle, event) {
                self.deliver(handle, reply);
                moved = true;
            }
            if drained {
                self.connections.remove(&handle);
                moved = true;
            }
        }

        // Flush the send queue as far as the stream permits.
        while !self.outbound.is_empty() {
            self.outbound.make_contiguous();
            let (batch, _) = self.outbound.as_slices();
            let sent = self.socket.send(batch)?;
            if sent == 0 {
                break;
            }
            moved = true;
            self.outbound.drain(..sent);
        }

        // Events queued by `deliver` during receive.
        for (handle, connection) in self.connections.iter_mut() {
            while let Some(event) = connection.poll() {
                moved = true;
                self.events.push_back((*handle, event));
            }
        }

        Ok(moved)
    }

    fn deliver(&mut self, handle: ConnectionHandle, event: ConnectionEvent) {
        if let Some(connection) = self.connections.get_mut(&handle) {
            connection.handle_event(event);
        }
    }

    /// A pollable for datagram arrival, for callers multiplexing several
    /// drivers in one poll set.
    pub fn incoming_pollable(&self) -> Pollable {
        self.socket.incoming_pollable()
    }

    /// A pollable for send-queue drain; meaningful when
    /// [`has_outbound`](Self::has_outbound) is `true`.
    pub fn outgoing_pollable(&self) -> Pollable {
        self.socket.outgoing_pollable()
    }

    /// Whether datagrams are queued waiting for the socket to accept them.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    /// The earliest timer deadline across connections, if any.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        self.connections
            .values_mut()
            .filter_map(|c| c.poll_timeout())
            .min()
    }
}
