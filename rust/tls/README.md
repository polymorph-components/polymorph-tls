# `polymorph-tls`

The algorithm profile's **curated** delivery: a pure-RustCrypto rustls
`CryptoProvider` and preconfigured TLS 1.3 configs for Rust guests that
link their TLS in-process. The policy itself — suites, groups, schemes,
preference orders, signing postures, per-item timing classes — is
[`polymorph-tls-profile`](../profile/README.md); this crate assembles the
implementations that deliver it.

A consumer of this crate makes no algorithm choices. It can always drop to
rustls directly and choose anything — these opinions bind only the crate's
users; that boundary is consent, not enforcement. The one rule the crate
makes unrepresentable rather than merely default is the signing rule: no
constructor accepts ECDSA or RSA private key material, and the provider's
key loader parses Ed25519 PKCS#8 only. In-guest class-D signing is not a
configuration this crate can express.

This is the *curated* delivery: it trades away the component's
memory-isolation benefit (session keys and any identity key share linear
memory with the application) for zero boundary plumbing. Deployments that
want the profile *enforced* — no configuration surface at all, secrets in
a separate component's memory — should compose the component delivery
instead (see the [repository README](../../README.md), "Design").

QUIC consumers: the core is deliberately QUIC-free. The QUIC
compatibility layer is [`polymorph-tls-quic`](../quic/README.md); the
embedder drives the I/O.

## Provider selection: `rustls-rustcrypto`

The provider is assembled from
[`rustls-rustcrypto`](https://github.com/RustCrypto/rustls-rustcrypto)
rather than an in-repo provider. Audit findings behind that decision:

- **Distribution**: no usable crates.io release exists (`0.0.2-alpha`,
  April 2024, rustls `^0.23`); the git repository is actively maintained.
  The dependency is a git reference pinned to the audited revision in
  `Cargo.toml` — a lockfile alone would not bind consumers of these
  crates, which resolve the git dependency from the manifest. Bumping the
  revision is a re-audit event.
- **QUIC**: upstream's QUIC support is an unwired stub — every suite
  carries `quic: None` and its `quic.rs` bodies are `todo!()`. The QUIC
  packet-protection layer therefore lives in this repository
  ([`polymorph-tls-quic`](../quic/README.md)), a candidate for upstream
  contribution.
- **Class-D signing code**: upstream compiles its ECDSA and RSA signing
  modules unconditionally. They are unreachable through this crate — the
  key loader only ever constructs Ed25519 signers, and no constructor
  accepts another key type — but the code is present in the dependency
  source rather than compiled out, unlike the sibling repository's
  `#[cfg(not(target_family = "wasm"))]` excision. Upstream feature flags
  (or an in-repo provider) would close that gap; recorded as residual.
- **RUSTSEC-2023-0071** (Marvin, the `rsa` crate): the `rsa` crate is in
  the tree for signature *verification* only, which the advisory does not
  affect. No RSA private-key operation is reachable: no API in this stack
  accepts RSA private key material.

## Backend verification on wasm32

The profile's timing classes hold only if the RustCrypto crates resolve to
their constant-time backends on wasm32. Verified by inspection of each
crate's cfg dispatch, and where possible by artifact:

- **AES is fixsliced** (`aes` 0.9): hardware backends exist only for
  x86/x86_64 and aarch64; every other target — wasm32 included — takes the
  soft backend, which is the fixsliced implementation (Adomnicai–Peyrin,
  [TCHES 2021](https://eprint.iacr.org/2020/1123)). `just audit` asserts
  the artifact: the release wasm binary must contain no AES S-box,
  inverse S-box, or T-table constants. A hit is the class-C failure mode
  (secret-indexed loads; Bernstein 2005, Osvik–Shamir–Tromer 2006).
- **GHASH is masked-multiply** (`ghash` → `polyval` 0.7): intrinsics exist
  only for x86/aarch64 CLMUL; all other targets take the soft backend,
  which implements the BearSSL constant-time method (integer
  multiplications over masked words with carry holes — class B's
  constant-latency-multiplier trust).
- **ChaCha20 / Poly1305** (`chacha20` 0.10, `poly1305` 0.9): soft backends
  on wasm32. Builds do not enable `+simd128`; if it is enabled later, the
  backend selection must be re-audited.
- **X25519 / P-256** (`x25519-dalek` 3, `p256` 0.14): the same
  constant-time implementations component-webcrypto's in-guest provider
  ships as class B (Montgomery ladder; complete Renes–Costello–Batina
  formulas).
- **Ed25519** (`ed25519-dalek` 3): complete addition laws, no
  per-signature secret nonce, constant-time scalar arithmetic.

## Raw public keys

The `rpk` module carries the mutually authenticated raw-public-key
posture (RFC 7250) — the peer-to-peer trust model where a bare Ed25519
key is the peer's identity. Its trust contract, timing notes, and
interoperability limits are in the module documentation and the
[profile document](../profile/README.md)'s "Raw public keys" section.
Nothing in it touches the provider: the same suites, groups, and
verification algorithms serve both trust models.

## Timing classes and residual assumptions

The classification and its sources are inherited from
[component-webcrypto's in-guest provider README](https://github.com/polymorph-components/polymorph-webcrypto/blob/main/rust/guest-provider/README.md).
Verification rows are secret-free (public keys over public signatures) and
therefore class-exempt.

| Item | Class | Implementation | Residual assumptions |
| --- | --- | --- | --- |
| Key schedule, transcript, Finished (SHA-256, HMAC, HKDF) | A | `sha2`, `hmac`, `hkdf` | None beyond compiler correctness. |
| `TLS_CHACHA20_POLY1305_SHA256` record protection | A + B | `chacha20` + `poly1305` (soft) | Constant-latency integer multiply (Poly1305). |
| `TLS_AES_128_GCM_SHA256` record protection | C + B | `aes` (fixsliced soft) + `polyval` (masked multiply) | Constant-latency integer multiply; JIT does not pathologically rewrite straight-line arithmetic. Never preferred; present as the RFC 8446 §9.1 conformance floor. |
| X25519 key agreement | B | `x25519-dalek` (Montgomery ladder) | Constant-latency integer multiply. |
| ECDH P-256 key agreement | B | `p256` (complete formulas) | Constant-latency integer multiply; benign JIT lowering. |
| Peer signature verification (Ed25519, ECDSA P-256/P-384, RSA PKCS#1/PSS) | exempt (secret-free) | `rustls-rustcrypto` verify set | Signing counterparts are class D and unreachable: the key loader constructs Ed25519 signers only. |
| Own CertificateVerify (Ed25519) | B | `ed25519-dalek` via `rustls-rustcrypto` | Constant-latency integer multiply. No per-signature secret nonce. |

The standing caveat applies unchanged: source-level constant-time
discipline defeats LLVM, and the runtime's JIT is a second optimizer free
to reintroduce what the source fought off
([CT-Wasm, POPL 2019](https://arxiv.org/abs/1808.01348)). This audit
establishes that the *bytecode* is the constant-time variant; the runtime
leg is empirical and per-runtime — the repository's
[`timing-lab/`](../../timing-lab/README.md) measures it, per wasmtime
version and per machine.
