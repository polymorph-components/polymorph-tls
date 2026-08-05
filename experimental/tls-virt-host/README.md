# `tls-virt-host`

The host-side counterpart of [`tls-virt`](../tls-virt/README.md): the
same transparent-TLS interposition on `wasi:sockets@0.3.0` — suffix-opted
name resolutions return minted handle addresses, connects to handle
addresses open the real transport and drive a TLS 1.3 handshake, the
guest speaks plain TCP and cannot observe the tunnel — implemented as a
wasmtime embedding whose sockets host provider wraps wasmtime-wasi's,
instead of as a wasm component composed in front of the guest.

The same demo component (`experimental/tls-virt/demo`) runs unmodified
against both: the two experiments interpose on the same surface from
opposite sides of the host boundary.

The tunnel's TLS runs the `lann-tls` profile configs natively
(tokio-rustls carrying `lann_tls::client_config`), so the algorithm
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

## Findings (contrasts with the component virtualizer)

- **The bindings-level obstacles vanish.** No structural-copy export
  package, no two-worlds bindgen split (the wit-bindgen payload-vtable
  dedup defect is a guest-bindings artifact), no conversion helpers:
  one implementation serves the one interface, and the wrapped
  implementation's types are the wrapper's types.
- **`listen` works by delegation.** Accepted sockets land in the
  *shared* resource table as ordinary wasmtime-wasi sockets, so every
  later operation on them delegates too. The component experiment's
  blocker — wrapping accepted nominal resources needs a resident task
  no export can host — does not arise when the wrapper and the wrapped
  implementation share a resource table.
- **Task scoping is not a concern; `Drop` is the awkward seam.** Host
  producers/consumers are polled by wasmtime directly, so nothing like
  the component's spawns-only-run-in-async-export-scope constraint
  exists. The one rough edge: the guest ending its transmit stream
  surfaces as the consumer's `Drop`, which cannot await — the TLS
  shutdown (close_notify, then FIN) must be spawned onto the runtime
  from `drop`, with the verdict resolving after the flush.
- **Delegation is trait-deep only.** wasmtime-wasi's trait impls are
  public and callable, but everything beneath them is `pub(crate)`:
  the `TcpSocket` state machine cannot be constructed or driven
  externally, and `SocketAddrCheck` cannot be invoked directly. In
  consequence the tunnel's own connect bypasses the sandbox's address
  check (its transport is native tokio); only the inner name
  resolution of opted-in names goes through wasmtime-wasi and its
  `allow-ip-name-lookup` gate. A production wrapper would need its own
  address policy for tunneled connects.

## Prototype limits

Trust roots are the repository's baked test fixtures
(`rust/quinn/tests/testdata/ca.der`), ALPN is not offered, socket
options on a tunneled socket reach the parked placeholder socket rather
than the tunnel's transport (as does `get-address-family`), the 0.2.x
sockets registered by `p2::add_to_linker_async` are not wrapped (a
guest importing them would bypass the tunnel; the demo imports only
0.3.0 sockets), and TLS failures surface as `connection-reset`/stream
closure with detail on stderr only.

This crate is excluded from the workspace: it is a native embedding and
cannot build for the workspace's wasm32-wasip2 target. It has its own
lockfile and builds on demand.

## Running

```sh
just smoke-tls-virt-host
```

Builds the demo component and this embedding, then runs two legs: the
tunnel leg against `openssl s_server -rev` (gates: handle address
returned, reversed echo with clean closes, TLS 1.3 handshake with
exactly the profile's cipher suites) and a passthrough leg against a
plain-TCP reverse echo (gates: real addresses returned, the whole
connection delegated to wasmtime-wasi).
