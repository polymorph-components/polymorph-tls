# Conformance

The cross-implementation conformance suite for `polymorph:tls`, on the
[`polymorph:test`](https://github.com/polymorph-components/polymorph-test)
harness: one shared guest suite runs, unmodified, against every
delivery of the algorithm profile a target composes in, and one
aggregate validates every run against the committed case inventory and
the target manifest.

```
guest-ct/       the suite: cases on the polymorph:test contract, the
                polymorph:tls surface imported as a consumer would;
                tests.lock is the committed case inventory
driver-ct/      target manifest (targets.toml), the recipes
                (justfile, module `conformance-ct`), the deltic
                drivers (deltic/), the committed matrix (matrix.md);
                results/ is generated
```

`just conformance` (from the repository root) runs the standing
matrix: build, inventory check, the wasmtime and deltic targets under
the pinned tooling, aggregate, and the committed-matrix diff.

## Targets

A target is a composition, not a runtime configuration: the suite is
`wac plug`-ged with one TLS stack, and the resulting artifact imports
only wasi and `polymorph:test/test-context`. The wasmtime rows run
under the generic component-test host runner; the deltic rows
runtime-link the same artifacts under the JSR-pinned deltic
runtime (`driver-ct/deltic/`) — one suite, one composition, two
engines.

| Target | Composition |
| --- | --- |
| `composed` | the `tls` world build: in-guest Ed25519 signing only |
| `composed-delegated` | the `tls-delegated` world build ⊕ the fixture signer (`examples/test-signer`) |
| `composed-delegated-webcrypto` | as above, but the signer is the `examples/webcrypto-signer` shim over a real `polymorph:webcrypto` provider; on demand (`just conformance-ct::run-webcrypto`), declared `optional` |
| `deltic-deno` | the `composed` artifact runtime-linked under deltic on stock Deno (no transpile, no engine flag) |
| `deltic-deno-delegated` | the `composed-delegated` artifact, likewise |
| `deltic-browser` | the `composed` artifact runtime-linked inside headless Chromium (gates in CI, locally `CONFORMANCE_BROWSER=1`; declared `optional`) |
| `deltic-browser-delegated` | the `composed-delegated` artifact, likewise |

In-suite QUIC cases are
[#29](https://github.com/polymorph-components/polymorph-tls/issues/29).

## Feature tags

One gated feature, `delegated-signer`: whether the composed TLS stack
carries a `polymorph:tls/signer`. Tagged cases exercise the delegated
posture where it exists; the `!delegated-signer` decline case asserts
delegated identities fail at construction where it does not. The
manifest (`driver-ct/targets.toml`) declares which targets lack the
feature; cases never probe for it.

## Lockfile and matrix

`guest-ct/tests.lock` pins the case inventory (names and tags);
regenerate with `just conformance-ct::lock-update` after a suite
change and commit the diff — the diff is the review surface. The
recorded artifact hash is provenance only; builds are not reproducible
across environments, so nothing may require it to match.

`driver-ct/matrix.md` is the committed aggregate of the standing
targets; CI regenerates it and `matrix-check` diffs. Refresh with
`just conformance-ct::matrix-update`.

## What stays outside

The suite covers the WIT surface's behavior. Deliberately not migrated
into it: `just interop` (cross-implementation against OpenSSL, Go, and
quic-go over real transports), `just smoke-quic` (QUIC over real
`wasi:sockets` UDP), the tls-virt smoke rigs (a different surface —
sockets interposition), `just bench`, `just audit`, and the timing lab
(statistical, per-runtime, non-gating by design).
