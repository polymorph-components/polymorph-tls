# The wasm-safe TLS 1.3 algorithm profile

This document is the profile: the algorithm policy that this repository's
two deliveries carry. The component delivers it *enforced* (no consumer
algorithm-configuration surface); the Rust guest library delivers it
*curated* (the ergonomic path, opinions binding only its users). Both
consume this crate, which states the policy as data and enforces the
signing rule by API shape.

## Timing-class basis

Whether an algorithm is safe to run in wasm is a timing-channel question.
The classification (classes A–D) and its sources are inherited from
[component-webcrypto's in-guest provider README](https://github.com/lann/component-webcrypto/blob/main/rust/guest-provider/README.md)
— read that first; this document only records the per-item assignments.
In brief: A is structurally constant-time; B trusts a constant-latency
multiplier and benign JIT lowering; C is constant-time only via a costly
variant (fixsliced AES); D is not realistically constant-time in portable
wasm and never runs in the guest.

## Cipher suites

In preference order:

| Suite | Class | Ruling |
| --- | --- | --- |
| `TLS_CHACHA20_POLY1305_SHA256` | A (ChaCha20) + B (Poly1305) | Preferred: the best wasm fit. |
| `TLS_AES_128_GCM_SHA256` | C (fixsliced AES) + B (masked-multiply GHASH) | Present because RFC 8446 §9.1 makes it mandatory-to-implement. Served **only** by a fixsliced, table-free AES; never preferred. |

`TLS_AES_256_GCM_SHA384` is **excluded**. It is a SHOULD, not a MUST
(RFC 8446 §9.1); it runs the same class-C AES machinery at higher cost plus
a second hash/HKDF chain (SHA-384); and the profile's AES presence is a
conformance floor, not an offering to expand. A peer that refuses both
suites above is out of scope.

## Key exchange

In preference order:

| Group | Class | Ruling |
| --- | --- | --- |
| `x25519` | B | Preferred: constant-time Montgomery ladder. |
| `secp256r1` | B | Present as RFC 8446 §9.1's MUST-support curve; complete Renes–Costello–Batina formulas. |

## Signature verification

Verification is secret-free — public keys over public signatures — and
therefore timing-class-exempt regardless of the algorithm. The profile
accepts the full RFC 8446 §9.1 mandatory-to-implement set plus Ed25519:

- `ed25519`
- `ecdsa_secp256r1_sha256` (and P-384)
- `rsa_pss_rsae_sha256` (and SHA-384/512)
- `rsa_pkcs1_sha256` (and SHA-384/512; certificates)

## Signing: the endpoint's own CertificateVerify

The one class-D-shaped operation in TLS 1.3. ECDSA and RSA signing are
class D — per-signature or per-message secrets in bignum arithmetic, with
a remote-exploitation lineage (Brumley–Boneh, Minerva, TPM-FAIL) that
targets exactly this shape: repeated signatures under one long-term key,
timing observable by an attacker who initiates handshakes. RFC 6979
deterministic ECDSA does not change the class: it removes RNG failure, not
the secret-dependent scalar arithmetic the timing channel reads.

The profile permits exactly two postures, and this crate's
`ServerIdentity` type has exactly those two variants:

1. **Ed25519 in-guest** (class B: no per-signature secret nonce,
   constant-time scalar arithmetic). `Ed25519Identity`'s constructor
   accepts only Ed25519 PKCS#8 material; ECDSA/RSA documents are rejected,
   not redirected.
2. **Delegated signing**: a caller-supplied signer holds the private key
   outside the guest. This is the posture for WebPKI identities.

The postures attach to whichever role authenticates, not to servers as
such. Under the WebPKI trust model only servers do, so that client path
holds no identity key and is entirely class ≤ B. Under mutual
authentication (the raw-public-key model below) the client signs its own
CertificateVerify too, governed by the same two postures.

### The PKI consequence

RFC 8446's mandatory-to-implement signature schemes constrain what an
endpoint *verifies*; the algorithm it *signs* with is determined by its
own certificate, so an Ed25519-only endpoint is conformant. But no public
CA issues Ed25519 certificates, so posture 1 requires a private PKI;
WebPKI (ECDSA/RSA) identities require posture 2.

## Raw public keys (RFC 7250)

The profile's peer-to-peer trust model: both endpoints present a bare
Ed25519 `SubjectPublicKeyInfo` in place of a certificate chain, the
connection is mutually authenticated, and the peer's public key is its
identity. `RpkIdentity` carries the same two signing postures as
`ServerIdentity`; there is no way to build a raw-public-key identity
around any algorithm but Ed25519.

What a verified connection authenticates: possession of the private key
behind the presented public key — nothing else. No names, no expiry, no
revocation. Timing-wise the model is strictly inside the profile: chain
verification (already secret-free) disappears entirely, peer
verification remains secret-free Ed25519, and each side's own signature
is class B in-guest or delegated.

Two scope notes:

- RFC 7250 requires support on both peers (rustls, OpenSSL 3.2+, GnuTLS,
  wolfSSL — not BoringSSL, Go, browsers, or platform stacks). It is a
  controlled-both-ends deployment shape, never a WebPKI substitute.
- It is specific to the profile's in-process deliveries. Host-terminated
  TLS providers generally cannot serve RFC 7250, so raw-public-key
  consumers are pinned to the in-guest implementation; the `lann:tls`
  component surface deliberately does not carry it.

## TLS versions

TLS 1.3 only. QUIC (RFC 9001) requires it, and TLS 1.2 would reopen
negotiation surface the profile exists to close.
