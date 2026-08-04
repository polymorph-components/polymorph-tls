//! Drives quinn-proto endpoints over `wasi:sockets` UDP.
//!
//! quinn-proto is sans-IO: it consumes received datagrams and emits
//! datagrams-to-send plus timer deadlines. This crate is the I/O half for
//! WASI 0.2 guests:
//!
//! - [`UdpSocket`]: a bound `wasi:sockets` UDP socket with the list-based
//!   (batched) datagram streams. `wasi:sockets` offers no GSO/GRO or
//!   `sendmmsg` beyond that batching, and none is assumed.
//! - [`Driver`]: pumps one `quinn_proto::Endpoint` and its connections
//!   over one socket — receive, timers, transmit — and surfaces
//!   application [`Event`]s. Waiting is pollable-based
//!   (`wasi:io/poll`), with deadlines from `wasi:clocks`.
//!
//! This crate has no dependency on any TLS specifics: it moves datagrams
//! and time. It compiles to an empty crate outside WASI targets.

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod addr;
#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod driver;
#[cfg(all(target_family = "wasm", target_os = "wasi"))]
mod socket;

#[cfg(all(target_family = "wasm", target_os = "wasi"))]
pub use driver::Driver;
#[cfg(all(target_family = "wasm", target_os = "wasi"))]
pub use socket::{SocketError, UdpSocket};
