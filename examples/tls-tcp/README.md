# `tls-tcp`

The real-transport demo and consumer example for the `lann:tls`
component: TLS over actual `wasi:sockets` TCP, composed the same way an
application would consume it.

Where `tls-loopback` wires the component's streams to itself in memory,
this app hands them to the transport with no pump loop of its own: the
connection's ciphertext output stream is passed directly as the TCP
socket's transmit stream, and the socket's receive stream is passed
directly as the connection's ciphertext input. The transform-pair shape
and `wasi:sockets@0.3` are deliberately compatible; the app only touches
cleartext.

## Running

Compose with the component, then run under Wasmtime with component-model
async, WASIp3, and network access:

```sh
cargo build --workspace --target wasm32-wasip2
wac plug --plug target/wasm32-wasip2/debug/lann_tls_component.wasm \
    target/wasm32-wasip2/debug/tls_tcp.wasm -o tls-tcp-composed.wasm

wasmtime run -W component-model-async=y -S p3 -S inherit-network \
    --dir "$PKI::/pki" tls-tcp-composed.wasm \
    server 127.0.0.1 0 /pki/leaf.der /pki/leaf-key.p8

wasmtime run -W component-model-async=y -S p3 -S inherit-network \
    --dir "$PKI::/pki" tls-tcp-composed.wasm \
    client 127.0.0.1 <port> localhost /pki/ca.der hello clean
```

The protocol is one LF-terminated request line and one LF-terminated
echo line; the client closes its write direction first. The client's
final argument names the close class it demands of the peer (see below);
`scripts/interop-tls.sh` drives these modes against OpenSSL and Go
peers, including peers that skip `close_notify`.

## What the close classes look like

Every connection ends with a two-layer report: the TLS direction futures
and the transport (socket) futures. The classes, as this demo renders
them:

- **`Clean`** — the peer sent TLS `close_notify`:

  ```text
  tls receive: clean close_notify
  transport receive: closed (FIN)
  ```

- **`Truncated`** — the peer closed the connection (an orderly FIN)
  without `close_notify`, the way much of the web does:

  ```text
  tls receive error: transport closed without TLS close_notify (possible truncation)
  transport receive: closed (FIN)
  ```

  The transport reports a perfectly normal close; only the TLS future
  reveals that the byte stream is unauthenticated at its end. Treating
  transport EOF as end-of-data is the truncation downgrade the
  interface's direction futures exist to prevent — an attacker who can
  drop packets can end a TLS stream early at any record boundary, and
  only `close_notify` proves the peer meant to stop there.

- **`Reset`** — the peer reset the connection (RST): as `Truncated`,
  but the transport layer also reports the failure, and the response
  may be lost with it:

  ```text
  tls receive error: transport closed without TLS close_notify (possible truncation)
  transport receive error: ErrorCode::ConnectionReset
  ```

A consumer that only needs the data-plus-verdict pattern reads the
cleartext stream to its close and then consults the direction future —
the stream's closure never waits on the future being read (see the
package README's "Connection lifecycle" section).
