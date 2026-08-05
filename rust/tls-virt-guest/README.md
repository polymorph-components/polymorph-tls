# `tls-virt-guest`

A `wasi:sockets@0.3.0` virtualizer component that adds TLS
transparently: an application that speaks plain TCP through
`wasi:sockets` is composed against this component instead of the host,
opts a hostname in by suffixing it with `.tls-virt.alt`, and every byte
it exchanges on that connection crosses the wire inside TLS 1.3 driven
by the composed `lann:tls` client. The application contains no TLS code
and cannot observe the tunnel; everything else — unsuffixed names,
literal addresses, UDP — passes through to the host unchanged.

The guest delivery of the tls-virt scheme: the name opt-in and
handle-address design live in [`tls-virt-common`](../tls-virt-common),
and [`tls-virt-wasmtime`](../tls-virt-wasmtime) implements the same
interposition host-side. Originally built to validate the analysis in
issue #14: that the `lann:tls` transform-pair interface (send/receive
wired before the handshake) can sit behind a connect-then-send sockets
surface, at the cost of one pipe and one splice task on the transmit
side. It can.

## Design

- **Opt-in by name.** `resolve-addresses("host.tls-virt.alt")` resolves
  `host` via the host resolver, stores the destination in the handle
  table, and returns a minted handle address (see `tls-virt-common` for
  the scheme).
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

Three composition/bindings facts this component established, each load
bearing for any sockets-shaped virtualizer:

- **Import and export the same interface; wire it in wac.** The
  component model's non-resource types are structural, so a world that
  imports and exports the same interfaces is the natural virtualizer
  shape, and composition needs no renamed interface copy: `compose.wac`
  assigns the virtualizer's `wasi:sockets/*` exports to the
  application's imports of the same names by explicit instance access,
  while the virtualizer's own imports continue to the host. (An earlier
  iteration exported a byte-copied `virt:sockets` package on the belief
  that same-name worlds could not be generated or composed; both halves
  of that belief were wrong.)

- **Share types across directions with
  `merge_structurally_equal_types`.** By default wit-bindgen generates
  distinct Rust types for the import and export sides of structurally
  identical interfaces, but deduplicates `future`/`stream` payload
  vtables by structural equivalence class — so the export side's
  payload types end up without `FuturePayload`/`StreamPayload` impls
  and cannot be constructed. `merge_structurally_equal_types: true` is
  the intended pairing: one Rust type per equivalence class (the rest
  become aliases), one payload vtable per class, and values cross
  directions with no conversion code at all — this crate carries no
  error or address mapping helpers. Only nominal types (resources)
  stay distinct, as they must. (An earlier iteration worked around the
  default with two `generate!` invocations over split import-only and
  export-only worlds; the option makes that unnecessary.)

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
  - Pass-through transport verdicts, like the ciphertext streams, pass
    **by handle** — with merged types they are simply returned as-is.
  - `listen` is **not supported**: each accepted host socket would need
    wrapping into an exported resource (resources are nominal, so no
    by-handle pass-through), and that wrapper needs a resident task no
    export on the listen path can host. The host delivery does not have
    this limit; see `tls-virt-wasmtime`.

## Limits

Trust roots are the repository's baked test fixtures
(`rust/quinn/tests/testdata/ca.der`), ALPN is not offered, socket
options set before a tunneled `connect` are not migrated to the real
socket, `get-address-family` on a tunnel reports IPv6 regardless of the
real transport, and TLS failures surface as `connection-reset`/stream
closure with detail on stderr only. See issue #16 for the
productionization gaps.

## Running

```sh
just smoke-tls-virt-guest
```

Builds the `lann:tls` component (plain world), this virtualizer, and
the demo app (`examples/tls-virt-demo`); composes them per
`compose.wac` (`wac compose`, with the import-satisfaction gate); then
runs the composed component against `openssl s_server -rev` on
localhost. The demo dials `localhost.tls-virt.alt`, sends one line, and
verifies the reversed echo and a clean close in both directions; the
script additionally asserts the resolver returned a handle address and
that openssl saw a TLS 1.3 handshake.
