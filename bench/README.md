# `bench/`

The performance measurement battery for issue #8's documented
tradeoff: what the profile's TLS/QUIC deliveries cost, natively and
under wasm, and what componentization adds on top. Non-gating by
design — statistical experiments cannot gate PRs; run on demand and
capture results with provenance.

```sh
just bench > bench/results/<date>-<host>.md
```

## Harnesses

- **`tls-bench`** — one binary, built natively and for wasm32-wasip2,
  running identical code in both environments so the native-vs-wasm
  delta isolates the environment, not the implementation. Rows: QUIC
  packet protection (`aead-seal`/`aead-open` per suite at 256 B, 1200 B
  and 16384 B, plus `header-mask`), TLS 1.3 `handshake` (Ed25519,
  fixture PKI, in-memory transport), and `tls-bulk` (record-path
  throughput per suite, in-memory transport). Native builds use
  hardware AES and carryless multiply through RustCrypto's runtime
  detection; wasm builds use the fixsliced software path the release
  audit pins.
- **`tls-component-bench`** — the same bulk and handshake work pushed
  through the composed `polymorph:tls` component's streams
  (`component-bulk`, `component-handshake`). Compared against
  `tls-bench` under the same runtime, the delta is the cost of
  componentization: canonical-ABI copies plus async plumbing. The
  component exports the record path, not packet protection, so the
  boundary cost is measured there — a deliberate deviation from the
  issue's literal wording. The suite is whatever the component
  negotiates (profile preference order: ChaCha20-Poly1305); the
  enforced delivery has no suite configuration by design.
- **`quic-native-bench`** and `quic-loopback bench <mib>` — end-to-end
  QUIC bulk throughput (`quic-bulk`): the same quinn-proto endpoints,
  profile TLS, one-process loopback topology and transfer loop, over
  `std::net` UDP natively and `wasi:sockets` UDP under Wasmtime.

## Methodology

Every row is `bench,<name>,<detail>,<unit>,<median>,<min>,<max>`: one
warmup batch, then a fixed batch count (9 for microbenchmarks, 5 for
stream bulk, 3 for QUIC transfers), reporting the median batch with the
observed extremes. Timing is `Instant` (the monotonic clock in both
environments). Iteration counts are fixed, sized so batches run for
milliseconds even at wasm speeds.

## Reading the numbers

- **Per-machine, per-runtime.** Results hold for one CPU, one rustc,
  one Wasmtime version; the report header records all three, and a
  runtime upgrade invalidates wasm rows. Do not compare rows across
  reports with different provenance.
- **Loopback, one process.** The bulk and QUIC rows run both endpoints
  in one process, so a row bounds the whole exchange (client seal plus
  server open), not a single sender. No network is involved.
- **Cores are not equal across rows.** The library rows are
  single-threaded. The composed-component row runs under Wasmtime's
  async executor and has been observed using more than two cores; its
  MB/s is not per-core efficiency.
- **Transport idioms differ by environment.** The wasm QUIC leg uses
  `wasi:sockets`' batched datagram streams; the native leg issues one
  `send_to` per datagram; neither has GSO/kTLS (unreachable from
  `wasi:sockets`, unused natively for comparability). The native QUIC
  driver busy-yields instead of parking, saturating a core by
  design.
- **QUIC rows ride the profile's preferred suite** (ChaCha20-Poly1305,
  negotiated); AES behavior is characterized by the `aead-*` rows.
- **Small-size ChaCha rows can favor wasm.** Native RustCrypto
  dispatches to SIMD backends whose per-call overhead shows at small
  inputs (see the 256 B and `header-mask` rows); this is a real
  property of the stack, not measurement noise.

Committed reports live in `bench/results/`, named by date and host.
