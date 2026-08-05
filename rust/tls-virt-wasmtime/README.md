# `tls-virt-wasmtime`

The host delivery of the tls-virt scheme, and the counterpart of
[`tls-virt-guest`](../tls-virt-guest): the same transparent-TLS
interposition on `wasi:sockets@0.3.0` — suffix-opted name resolutions
return minted handle addresses, connects to handle addresses open the
real transport and drive a TLS 1.3 handshake, the guest speaks plain
TCP and cannot observe the tunnel — implemented as a wasmtime embedding
whose sockets host provider wraps wasmtime-wasi's, instead of as a wasm
component composed in front of the guest. The name opt-in and
handle-address design live in [`tls-virt-common`](../tls-virt-common).

The same demo component (`examples/tls-virt-demo`) runs unmodified
against both deliveries: they interpose on the same surface from
opposite sides of the host boundary. This delivery additionally
interposes `wasi:sockets@0.2.x`, which the guest delivery does not: a
plain `std::net` Rust guest (`examples/tls-virt-demo-p2`) — std on
wasm32-wasip2 sits on the 0.2 interfaces — tunnels the same way, with
no wasm-specific code at all.

The tunnel's TLS runs the `polymorph-tls` profile configs natively
(tokio-rustls carrying `polymorph_tls::client_config`), so the algorithm
profile stays the single policy source; the smoke rig gates that the
offered cipher suites are the profile's, verbatim.

## How the wrapping works

- **wasmtime-wasi's p3 linker surface is per-subsystem.** The embedding
  takes `p3::{cli,clocks,filesystem,random}::add_to_linker` stock and
  skips `p3::sockets`, registering the two sockets interfaces through
  their generated per-interface `add_to_linker`s with its own
  `HasData` projection (`VirtSockets`/`VirtView`).
- **The provider implements wasmtime-wasi's own generated traits**
  (`HostTcpSocket`, `HostTcpSocketWithStore`, …), so it shares
  wasmtime-wasi's types end to end, and pass-through is a direct call
  into wasmtime-wasi's public trait impls on `WasiSocketsCtxView` and
  `WasiSockets` — no error or address type mapping anywhere. The
  delegated accessor is re-projected with `Accessor::with_getter` /
  `Access::new`.
- **Tunnels are a side map keyed by the socket's table index.** Every
  guest socket is a real wasmtime-wasi table entry; a tunneled connect
  leaves that entry unconnected and parks the TLS stream halves in the
  side map. Dispatch checks the side map first, else delegates.
- **The data path is the host producer/consumer model.** The guest's
  transmit stream pipes into a `StreamConsumer` writing the TLS write
  half; the receive stream is a `StreamProducer` reading the TLS read
  half; the direction verdicts are oneshot-backed `FutureReader`s —
  the same shapes as wasmtime-wasi's own TCP implementation.
- **The 0.2 generation is wrapped separately** (`src/p2.rs`), against
  the same handle table: only `sockets/tcp` and
  `sockets/ip-name-lookup` carry custom implementations (`udp`,
  `network`, `instance-network`, and the create-socket interfaces are
  registered stock). The 0.2 shapes differ where it matters:
  `start`/`finish-connect` drive the handshake as a polled background
  task with a custom pollable; the data path is `wasi:io` streams —
  the receive stream pulls from the TLS read half inside
  `Pollable::ready`, while the send direction needs a resident writer
  task, because a 0.2 guest may `check-write`/`write` and never poll
  the stream again; `shutdown(send)` and output-stream drop both
  become close_notify; and name lookup drains the delegated
  `resolve-address-stream` through the wrapped resource before
  yielding the one handle address. Unlike the 0.3 tunnel path, 0.2
  tunnel connects **do** pass the sandbox address check against the
  real destination: the 0.2 `network` resource exposes
  `check_socket_addr` publicly.

## Findings (contrasts with the guest virtualizer)

- **The bindings-level concerns vanish.** No type merging to opt into
  (the guest delivery needs wit-bindgen's
  `merge_structurally_equal_types` to share types across its import
  and export directions), no conversion helpers: one implementation
  serves the one interface, and the wrapped implementation's types are
  the wrapper's types.
- **`listen` works by delegation.** Accepted sockets land in the
  *shared* resource table as ordinary wasmtime-wasi sockets, so every
  later operation on them delegates too. The guest delivery's blocker —
  wrapping accepted nominal resources needs a resident task no export
  can host — does not arise when the wrapper and the wrapped
  implementation share a resource table.
- **Task scoping is not a concern; `Drop` is the awkward seam.** Host
  producers/consumers are polled by wasmtime directly, so nothing like
  the guest's spawns-only-run-in-async-export-scope constraint exists.
  The one rough edge: the guest ending its transmit stream surfaces as
  the consumer's `Drop`, which cannot await — the TLS shutdown
  (close_notify, then FIN) must be spawned onto the runtime from
  `drop`, with the verdict resolving after the flush.
- **Delegation is trait-deep only.** wasmtime-wasi's trait impls are
  public and callable, but everything beneath them is `pub(crate)`:
  the `TcpSocket` state machine cannot be constructed or driven
  externally, and `SocketAddrCheck` cannot be invoked directly. In
  consequence the tunnel's own connect bypasses the sandbox's address
  check (its transport is native tokio); only the inner name
  resolution of opted-in names goes through wasmtime-wasi and its
  `allow-ip-name-lookup` gate. A production wrapper would need its own
  address policy for tunneled connects.

## Limits

Trust roots are the repository's baked test fixtures
(`rust/quinn/tests/testdata/ca.der`), ALPN is not offered, socket
options on a tunneled socket reach the parked placeholder socket rather
than the tunnel's transport (as does `get-address-family`), and TLS
failures surface as `connection-reset`/stream closure with detail on
stderr only. On the 0.3 path, tunnel connects bypass the sandbox
address check (see the findings above); the 0.2 path enforces it. See
issue #16 for the productionization gaps.

## Running

```sh
just smoke-tls-virt-wasmtime
```

Builds the demo components and this embedding, then runs a tunnel leg
and a passthrough leg per sockets generation: tunnel legs against
`openssl s_server -rev` (gates: handle address returned, reversed echo
with clean closes, TLS 1.3 handshake with exactly the profile's cipher
suites), passthrough legs against a plain-TCP reverse echo (gates: real
addresses returned, the whole connection delegated to wasmtime-wasi).
The 0.2 legs run the `std::net` guest.
