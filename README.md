# `lann:tls`

A TLS 1.3 WIT package and pure-wasm implementation, designed to serve QUIC
over `wasi:sockets`. A sibling of
[`lann:webcrypto`](https://github.com/lann/component-webcrypto) and
[`lann:webrtc-datachannels`](https://github.com/lann/webrtc-datachannels),
following the same architecture.

**Status: designed, not built.** This repository currently holds the design
and its open requirements (see the
[issue tracker](https://github.com/lann/component-tls/issues)); no WIT or
implementation exists yet.

## Why pure-wasm TLS 1.3 is plausible

Whether an algorithm is safe to run in wasm is a timing-channel question.
This repository inherits the class A–D classification from
[`component-webcrypto`'s in-guest provider](https://github.com/lann/component-webcrypto/blob/main/rust/guest-provider/README.md)
— wasm makes no constant-time guarantee for any instruction, so algorithms
are classed by how much their best software implementation must trust the
machine below it, weighted by the blast radius of a small leak. TLS 1.3's
secret-bearing surfaces walk through it as follows.

- **Key schedule and session machinery** — HKDF, transcript hashing, the
  Finished MAC, session tickets, key update: class A (structurally
  constant-time).
- **Key exchange** — X25519 or ECDH P-256, one ephemeral scalar
  multiplication per handshake: class B (constant-time given a
  constant-latency multiplier and benign JIT lowering).
- **Peer authentication** — certificate-chain and CertificateVerify
  *verification* is secret-free, hence exempt regardless of the peer's
  algorithm. A pure-wasm TLS 1.3 client without client certificates never
  touches class D at all.
- **Packet protection** — ChaCha20-Poly1305 is class A/B and the preferred
  suite; `TLS_AES_128_GCM_SHA256` is mandatory-to-implement (RFC 8446
  §9.1), so a conformant stack carries it as fixsliced, table-free AES
  (class C: constant-time only via the costly variant) and never prefers
  it. QUIC header protection follows the same split.
- **The one class-D hole** — the endpoint's *own* CertificateVerify
  signature. ECDSA and RSA signing are class D, and the attack lineage
  (Brumley–Boneh, Minerva, TPM-FAIL) targets exactly this shape: repeated
  signatures under the same long-term key with attacker-observable timing,
  and the attacker initiates handshakes. Ed25519 signing is class B, so an
  Ed25519 identity key closes the hole in-guest — RFC 8446's
  mandatory-to-implement signature schemes constrain what an endpoint can
  *verify*, while the algorithm it *signs* with is determined by its own
  certificate, so an Ed25519-only endpoint remains conformant. No public CA
  issues Ed25519 certificates, so that posture requires a private PKI;
  WebPKI identities (ECDSA/RSA) require delegating the signature out of the
  guest instead.

## Design

The central ruling: **the algorithm profile is the primary artifact**, and
it has two deliveries.

A second ruling orders the goals: **the primary goal is a generally-useful
TLS interface and implementation.** QUIC over `wasi:sockets` is the
motivating consumer, and quinn compatibility is a real but secondary
requirement — delivered as a separate compatibility layer and used as the
validation vehicle, never part of the core library.

- **The profile** fixes the algorithm policy once: ChaCha20-Poly1305
  preferred; fixsliced `TLS_AES_128_GCM_SHA256` present for conformance,
  never preferred; X25519 and P-256 key exchange; the full
  mandatory-to-implement verification set (secret-free); signing is
  Ed25519 in-guest or delegated — class-D signing never runs in the guest.
- **The component is the profile's enforced delivery.** Consumers get no
  algorithm configuration surface at all. The CertificateVerify signer is
  a world *import* — satisfiable by a host-side provider, left unwired for
  Ed25519-only deployments — so in-guest class-D signing is structurally
  unrepresentable, in the same way `component-webcrypto`'s in-guest
  provider withholds class-D exports. The component imports `wasi:sockets`
  (UDP), `wasi:clocks`, and `wasi:random`; its export shape should stay
  swappable with an eventual host-terminated TLS provider (the `wasi-tls`
  proposal), so a composition chooses in-guest versus host TLS at
  `wac plug` time the way `component-webcrypto` compositions choose their
  crypto provider.
- **The Rust guest library is the profile's curated delivery.** Same
  profile underneath, delivered as the ergonomic path for Rust guests. Its
  one near-airtight rule is API shape rather than configuration default:
  no constructor accepts class-D private key material; signing is only
  ever a caller-supplied trait object.

The implementation path is assembly, not invention: rustls with a pure-
RustCrypto `CryptoProvider` at the core; for the QUIC leg, `quinn-proto`
(sans-IO QUIC) driven over `wasi:sockets` UDP by an adapter this repository
owns.

## Performance posture

Honest expectations, to be replaced by measurements (the documented
tradeoff is a deliverable, not a caveat):

- wasm has no AES-NI and no carryless multiply, so fixsliced AES-GCM plus
  software GHASH runs an order of magnitude or more off native hardware;
  ChaCha20-Poly1305 fares much better and is preferred for exactly this
  reason.
- QUIC pays per-packet AEAD, and no kTLS/GSO offload is reachable from
  `wasi:sockets` (datagram batching only). Suitable for control planes and
  moderate throughput, not line rate.
- Component-boundary copies are noise relative to in-wasm crypto: the
  canonical ABI transfers at memcpy cost (a fraction of a cycle per byte)
  against tens of cycles per byte for the ciphers. The tradeoff that
  matters is wasm versus native, not library versus component.

## Threat model

The same frame as the sibling's in-guest provider. The host is already
trusted — anyone running TLS in a wasm guest has conceded that the host can
read all key material. The marginal adversaries are co-tenants and remote
observers: do **not** deploy this where hostile co-tenancy is part of the
threat model (wasm gives memory isolation, not microarchitectural
isolation). Against remote observers, the profile keeps every secret-bearing
operation at class ≤ B except the fixsliced AES-GCM conformance floor —
and wasm's timing story is per-runtime-empirical, never guaranteed (the
two-compiler problem: source-level constant-time discipline defeats LLVM,
and the JIT is a second optimizer free to reintroduce what the source
fought off), so empirical timing verification is part of the design, not an
afterthought.

What the component buys over a linked TLS library is memory isolation for
long-lived secrets: session keys and the identity key live in the TLS
component's linear memory, unreachable from consumers — a memory-safety bug
or malicious dependency in the application cannot exfiltrate them
(Heartbleed is precisely the co-linked-TLS-library failure mode). Timing is
the remaining channel; memory is closed.
