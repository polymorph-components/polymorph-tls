# `lann:tls`

A TLS 1.3 interface for WebAssembly components. Connections are stream
transforms: the consumer owns the transport and hands byte streams across
the boundary; the implementation never touches a socket. The package
carries both directions — outgoing (`client`) and incoming (`server`) —
and a delegated-signing seam (`signer`) for identities whose private keys
must not enter the component.

## Algorithm profile

Consumers make no algorithm choices; there is no configuration surface.
Implementations of this package fix a single TLS 1.3 policy:

- Cipher suites: `TLS_CHACHA20_POLY1305_SHA256` preferred;
  `TLS_AES_128_GCM_SHA256` supported, never preferred.
  `TLS_AES_256_GCM_SHA384` is not offered.
- Key exchange: X25519 preferred; `secp256r1` supported.
- Peer signature verification: `ed25519`, `ecdsa_secp256r1_sha256`,
  ECDSA P-384, RSA PKCS#1 v1.5 and RSA-PSS with SHA-256/384/512.
- The endpoint's own CertificateVerify signature: Ed25519, or delegated
  through the `signer` interface. See "Signing policy".

A consumer that needs a different policy is out of scope by construction.

## Connection lifecycle

`connector` and `acceptor` share one contract.

1. Construct the resource (trust roots for `connector`, an `identity`
   for `acceptor`).
2. Call `send` exactly once: pass the stream you will write application
   data into; keep the returned ciphertext stream and forward it to your
   transport's transmit side.
3. Call `receive` exactly once: pass the stream carrying bytes from your
   transport's receive side; keep the returned cleartext stream and read
   application data from it.
4. Call `connect` (or `accept`). It drives the handshake over the wired
   streams and resolves with `connection-info` when the peer is
   authenticated and application data may flow.

Data before the handshake method resolves is buffered, not delivered:
this package has no 0-RTT surface.

Shutdown: closing the cleartext stream you write into causes a TLS
`close_notify` and then closes the ciphertext stream toward your
transport. In the other direction, the cleartext stream you read from
closes when the peer closes its write direction; consult that
direction's future to distinguish a clean TLS close from transport
truncation — treating truncation as end-of-data is a downgrade hazard.

The futures returned by `send` and `receive` resolve when their
direction finishes: `ok` for a clean close, an `error` for handshake
failure, peer misbehavior, or transport failure. Stream closures never
wait on the futures: every stream reaches its final state from protocol
events alone, so a consumer may read a direction's future after
draining its stream, concurrently, or never.

## Signing policy

The endpoint's own CertificateVerify signature is the one TLS 1.3
operation that repeatedly exercises a long-term private key against
attacker-observable timing. This package admits exactly two postures:

- **Ed25519 in the component** (`identity.ed25519`): the key enters the
  component; constant-time software implementations of Ed25519 are
  well-established. The constructor accepts only Ed25519 PKCS#8
  documents.
- **Delegated** (`identity.delegated`): the component holds only the
  certificate chain; signatures come from the composed `signer`
  implementation, and the private key lives wherever that implementation
  keeps it.

No API in this package accepts an ECDSA or RSA private key. Deployments
with such identities (for example, WebPKI certificates) use the
delegated posture.

## Worlds

- `tls`: no signer import. `identity.delegated` fails at construction.
  Choose this when identities are Ed25519 and the composition should not
  carry a signing capability at all.
- `tls-delegated`: imports `signer`. Choose this for delegated
  identities, and satisfy the import with a host-side provider or
  another component.

## Relationship to `wasi-tls` (recorded ruling)

This package is its own interface, not an implementation of
[`wasi-tls`](https://github.com/WebAssembly/wasi-tls). The ruling and its
reasons:

- `wasi-tls`'s WASI 0.2 interface is `@unstable`, client-only, and built
  around the host minting `wasi:io` streams — a shape a guest component
  cannot implement without virtualizing `wasi:io` itself. Aligning with
  it would tie this package to a shape its own authors are moving away
  from.
- The connection shape here (stream-transform pairs plus a completion
  future, over component-model async `stream<u8>`) deliberately shares
  the idiom of `wasi-tls`'s 0.3 draft `connector.send`/`receive`. If a
  host-terminated TLS provider standardizes on that shape, adapting
  between it and this package is mechanical.
- This package adds what `wasi-tls` does not yet carry and this design
  requires: a server surface, the identity postures, and the structural
  signer seam.

Divergences from any future `wasi-tls` shape are to be resolved
deliberately — narrowed, adapted at composition time, or recorded here —
never accumulated silently.

## Design notes

- **Signer seam shape**: a minimal bespoke interface (scheme + complete
  RFC 8446 §4.4.3 message in, TLS wire-format signature out) rather than
  reusing `lann:webcrypto`'s per-algorithm signing interfaces. Reuse
  would couple this package's import surface to another package's
  key-resource model, and a shared error resource cannot cross the
  import/export direction anyway (resource types are instance-bound). A
  small shim component can adapt a `lann:webcrypto` provider to
  `signer`.
- **`signer` errors are strings**, not the `types.error` resource: the
  signer is implemented on the other side of the boundary from this
  package's implementation, which could not mint or interpret a foreign
  error resource.
- **Identity provisioning is by constructor argument** (certificate
  chains and, for Ed25519, key material as explicit parameters) rather
  than via a configuration interface or runtime-config keys: the values
  are per-connection-endpoint data, and explicit arguments keep the
  no-configuration-surface property inspectable.
- **QUIC**: TLS-for-QUIC is not TLS-over-a-stream (RFC 9001); serving it
  would require a handshake-engine interface that exports per-epoch
  traffic secrets. That interface is deliberately deferred; nothing in
  this package's shape precludes adding it as a separate interface
  later.
