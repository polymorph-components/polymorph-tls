# `polymorph-tls-quic`

quinn compatibility for the profile. The repository's primary artifact is
TLS ([`polymorph-tls`](../tls/README.md) is the curated core); this crate is
the QUIC leg, kept out of the core library's dependency graph: everything
quinn-proto needs to run the profile's TLS 1.3 over QUIC.

## What is here, and why it exists

- **RFC 9001 packet and header protection** (`packet.rs`), implementing
  `rustls::quic::Algorithm` for the profile's two suites over the same
  RustCrypto primitives the record layer uses. Exists because upstream
  `rustls-rustcrypto` ships its QUIC module as an unwired `todo!()` stub
  (see the [core crate's audit](../tls/README.md)); a candidate for
  upstream contribution. Header-protection masks and the
  ChaCha20-Poly1305 packet path are pinned to the RFC 9001 Appendix A
  test vectors.
- **QUIC-wired suites** (`suites.rs`): rustls-rustcrypto's TLS 1.3 suites
  rebuilt with the `quic` slot populated. The TLS machinery (hash, HKDF,
  record AEAD) is upstream's unchanged.
- **quinn-proto session glue** (`session.rs`), adapted from quinn-proto's
  `crypto/rustls.rs`: upstream gates that module behind features that
  hard-wire ring or aws-lc into the build, which the profile's
  pure-RustCrypto posture excludes. The retry integrity tag (RFC 9001
  §5.8) is computed with the `aes-gcm` crate.
- **Endpoint keys** (`keys.rs`): stateless-reset HMAC-SHA-256 and the
  HKDF-SHA-256 → AES-256-GCM handshake-token construction, mirroring
  quinn's ring backend so tokens keep the same structure.

The provider and config constructors here carry the same policy as the
core crate — profile suites and groups in preference order, secret-free
verification breadth, Ed25519-only key loading — plus the settings QUIC
mandates (ALPN required, RFC 9001 §8.1; `max_early_data_size` of
`u32::MAX`). Both trust models are served: WebPKI
(`client_config`/`server_config`) and mutually authenticated raw public
keys (`rpk_client_config`/`rpk_server_config`, RFC 7250) — see
[`polymorph-tls`'s `rpk` module](../tls/README.md) for the trust contract.

## Timing notes beyond the core table

| Item | Class | Implementation | Residual assumptions |
| --- | --- | --- | --- |
| Packet protection, both suites | as record protection | `chacha20poly1305`, `aes-gcm` (fixsliced) | As the [core table](../tls/README.md)'s record-protection rows. |
| Header protection, ChaCha20 suite | A | raw `chacha20` keystream over the sample | None beyond compiler correctness. |
| Header protection, AES suite | C | single-block fixsliced `aes` encrypt of the sample | As the core AES row. |
| Header-protection mask application | A | uniform XOR over the caller's packet-number region, gated by `subtle` arithmetic selection (never by trip count or a branch on the pn-length bits) | Decrypt's region is always the full 4 bytes (RFC 9001 §5.4.2); encrypt's region length equals the pn length — a quinn calling shape this crate cannot widen. |
| Retry integrity tag | exempt (secret-free) | `aes-gcm` under the published RFC 9001 §5.8 constants | The key is a public constant; nothing secret transits. |
| Stateless reset key | A | `hmac` + `sha2` | None beyond compiler correctness. |
| Handshake token protection | C + B | `hkdf` → `aes-gcm` (fixsliced) | As the core AES row. Tokens carry no TLS secrets. |
