# `tls-virt`

An experimental `wasi:sockets@0.3.0` virtualizer that adds TLS
transparently: an application that speaks plain TCP through
`wasi:sockets` is composed against this component instead of the host,
opts a hostname in by suffixing it with `.tls-virt.alt`, and every byte
it exchanges on that connection crosses the wire inside TLS 1.3 driven
by the composed `lann:tls` client. The application contains no TLS code
and cannot observe the tunnel; everything else — unsuffixed names,
literal addresses, UDP — passes through to the host unchanged.

This prototype exists to validate the analysis in issue #14: that the
`lann:tls` transform-pair interface (send/receive wired before the
handshake) can sit behind a connect-then-send sockets surface, at the
cost of one pipe and one splice task on the transmit side. It can.

## Design

- **Opt-in by name.** `resolve-addresses("host.tls-virt.alt")` resolves
  `host` via the host resolver, stores `(hostname, addresses)` in a
  table, and returns a **handle address**: a random 64-bit suffix under
  a random ULA /64 prefix (RFC 4193 `fd00::/8`) minted once per
  instance. Handle addresses never appear on the wire.
- **Connect to a handle** opens a real connection to a stored address
  (preferring IPv6) and drives the TLS handshake with the stored
  hostname (SNI + certificate verification). Ciphertext streams are
  wired socket↔TLS by handle; the application's transmit stream, which
  arrives only at `send`, is spliced into a pre-wired cleartext pipe.
  `get-remote-address` keeps reporting the handle address.
- **Pass-through preserves the surface.** Non-handle connects, option
  get/setters, and all of UDP delegate to a host socket of the same
  shape.

## Findings

Three composition/bindings facts this prototype established, each load
bearing for any sockets-shaped virtualizer:

- **Export a renamed structural copy, rewire it in wac.** One component
  cannot cleanly import and export the same interface for bindings
  generation, so the exports are a byte-copy of `sockets.wit` under the
  package name `virt:sockets`. Instance types are structural in the
  component model: `compose.wac` assigns the virtualizer's
  `virt:sockets/*` exports to the application's `wasi:sockets/*`
  imports and the name difference is immaterial, while the
  virtualizer's own `wasi:sockets/*` imports continue to the host.

- **Mixed import/export worlds trip a wit-bindgen 0.60 defect; generate
  the directions separately.** wit-bindgen deduplicates `future`/
  `stream` payload vtables by *structural* type equality across the
  whole world (`get_representative_type`, a union-find in
  `wit-bindgen-core`'s type information). With `wasi:sockets` imported
  and its structural copy exported, the export-side
  `future<result<_, error-code>>` payload is folded onto the
  import-side representative, and its distinct Rust type
  (`exports::…::ErrorCode`) never receives a `FuturePayload` impl —
  `wit_future::new` for the export side then fails to compile. Only
  nominal types (resources) escape the folding. The generator's
  assumption that "structurally equal types resolve to the same Rust
  type" is false across directions. Splitting the world into an
  imports-only and an exports-only world, with one `generate!`
  invocation each, keeps the payload maps separate; both invocations
  share one runtime, so handles flow freely between them.

- **Only async-lifted exports have a task scope; structure the
  virtualizer around `connect`.** wit-bindgen spawns are polled by the
  executor of the enclosing async-lifted export task; a spawn from a
  sync-lifted export (`send`, `receive`) is queued and never polled.
  All long-lived tunnel work — the transmit splice and the TLS-verdict
  mappers — is therefore spawned inside async `connect`, whose task
  stays alive (after returning its value) until the connection ends;
  the same pattern as the `lann:tls` component's own pump. The sync
  exports only hand out endpoints minted at connect time, and the
  sync-export error paths use writer-drop defaults
  (`wit_future::new(default)`) instead of tasks. Two consequences:
  - Pass-through transport verdicts are reissued **by handle**
    (`take_handle` + rewrap): legal because the two payload types are
    structurally one WIT type, and task-free.
  - `listen` is **not supported**: each accepted host socket would need
    wrapping into an exported resource (resources are nominal, so no
    by-handle pass-through), and that wrapper needs a resident task no
    export on the listen path can host.

## Prototype limits

Deliberate scope cuts, over and above the findings: trust roots are the
repository's baked test fixtures (`rust/quinn/tests/testdata/ca.der`),
ALPN is not offered, socket options set before a tunneled `connect` are
not migrated to the real socket, `get-address-family` on a tunnel
reports IPv6 regardless of the real transport, and TLS failures surface
as `connection-reset`/stream closure with detail on stderr only.

## Running

```sh
just smoke-tls-virt
```

Builds the `lann:tls` component (plain world), the virtualizer, and the
demo app; composes them per `compose.wac` (`wac compose`, with the
import-satisfaction gate); then runs the composed component against
`openssl s_server -rev` on localhost. The demo dials
`localhost.tls-virt.alt`, sends one line, and verifies the reversed
echo and a clean close in both directions; the script additionally
asserts the resolver returned a handle address and that openssl saw a
TLS 1.3 handshake.
