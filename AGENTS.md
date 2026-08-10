# AGENTS.md

Guidance for automated agents (and humans) working in this repository.

## What this repository is

`polymorph:tls`: a TLS 1.3 WIT package plus a pure-wasm implementation, with
a noq-proto compatibility layer serving QUIC embedders. A sibling of
[`polymorph:webcrypto`](https://github.com/polymorph-components/polymorph-webcrypto) and
[`polymorph:webrtc-datachannels`](https://github.com/polymorph-components/polymorph-webrtc-datachannels),
deliberately mirroring their architecture — prefer clarity and correctness
over features. See [`README.md`](README.md) for the design.

The repository holds the `polymorph:tls` WIT package (`wit/`, with its README
of recorded rulings), the Rust deliveries, and their validation rigs. The
open requirements live in the GitHub issue tracker, and the README is the
design record.

## Layout

- `wit/` — the `polymorph:tls` package; `wit/README.md` carries the package
  contracts and recorded rulings (wasi-tls relationship, signer seam,
  worlds).
- `rust/profile` — the algorithm profile as data plus the identity types;
  the single policy source. Its README is the profile document.
- `rust/tls` — the curated core delivery: profile provider + TLS 1.3
  configs. Deliberately QUIC-free. Its README records the provider audit.
- `rust/quic` — QUIC compatibility: RFC 9001 packet protection (multipath
  nonces included), noq-proto crypto wiring, endpoint keys. The QUIC
  deliverable; the embedder brings the transport.
- `rust/component` — the `polymorph:tls` component (enforced delivery);
  wasm-only cdylib, `delegated-signer` feature selects the
  `tls-delegated` world.
- `rust/tls-virt-common` — the tls-virt scheme (suffix-opted names,
  minted handle addresses, destination selection), shared by both
  tls-virt deliveries; its lib docs are the scheme record.
- `rust/tls-virt-guest` — the guest tls-virt delivery: a `wasi:sockets`
  virtualizer component adding transparent TLS via the composed
  `polymorph:tls` client; carries `compose.wac` and the record of the
  bindings findings in its README.
- `rust/tls-virt-wasmtime` — the host tls-virt delivery: a wasmtime
  embedding whose sockets provider wraps wasmtime-wasi's; native crate,
  excluded from wasm builds (`build-wasm` passes `--exclude`).
- `examples/quic-loopback` — the QUIC smoke-test guest; also carries
  the QUIC interop endpoint modes and its own
  noq-proto-over-`wasi:sockets` driver (validation machinery, not a
  delivery).
- `examples/test-signer`, `examples/webcrypto-signer` — the
  delegated-signer plugs: the self-contained fixture signer, and the
  shim adapting a `polymorph:webcrypto` provider to `polymorph:tls/signer`;
  both are conformance-target compositions.
- `conformance/` — the cross-implementation conformance suite on the
  [`polymorph:test`](https://github.com/polymorph-components/polymorph-test)
  harness: the shared guest suite (`guest-ct`, its committed
  `tests.lock` the case inventory) composed with each delivery of the
  profile, the target manifest and recipes (`driver-ct`), and the
  committed matrix. See `conformance/README.md`.
- `examples/tls-tcp` — the real-transport demo guest: the composed
  component over `wasi:sockets` TCP; also the TLS interop endpoint.
- `examples/tls-virt-demo`, `examples/tls-virt-demo-p2` — the plain-TCP
  demo guests: the wasip3 app both tls-virt rigs run unmodified, and
  the `std::net` app (`wasi:sockets@0.2.x` via Rust std) for the
  wasmtime delivery's 0.2 interposition.
- `bench/` — the performance battery (tls-bench, tls-component-bench,
  quic-native-bench) and its captured, provenance-stamped reports in
  `bench/results/`; its README records methodology and caveats.
- `timing-lab/` — the dudect-style statistical timing lab for the
  deliveries' protocol-level secret-bearing surfaces; its README carries
  the methodology, the detection limits, and the hardware-floor record.
- `scripts/` — audit helper, the interop harnesses (with their Go
  peer in `scripts/interop/peer`), the tls-virt smoke harnesses, and
  the bench runner.

## Checks

| Recipe | Verifies |
| --- | --- |
| `just check` | fmt, clippy (all features), workspace tests (RFC 9001 vectors, profile/provider pinning, class-D key rejection), wasm build |
| `just ci` | every gating CI job's body, exactly as CI runs it — each CI job runs one gha:: job recipe (.github/justfile). The timing lab is schedule-only and excluded |
| `just conformance` | the cross-implementation conformance suite (see `conformance/README.md`): the shared guest suite composed with each delivery — the `tls` world's in-guest Ed25519 posture and the `tls-delegated` world with the fixture signer — run under the pinned component-test runner, runtime-linked under deltic on stock Deno (the deltic-deno targets — no transpile, no engine flag; release-pinned in `conformance/driver-ct/deltic/`), and runtime-linked in headless Chromium (the deltic-browser targets; CI or CONFORMANCE_BROWSER=1), with import-satisfaction and signer-reachability gates, validated against the committed case inventory (`tests.lock`) and target manifest, and diffed against the committed matrix. `just conformance-ct::run-webcrypto` (on demand: clones the sibling repo) adds the delegated posture over a real `polymorph:webcrypto` provider |
| `just smoke-quic` | QUIC over `wasi:sockets` UDP under Wasmtime |
| `just smoke-tls-virt` | both tls-virt deliveries against `openssl s_server` over real TCP (needs openssl + python3): the composed guest virtualizer (handle-address and import-satisfaction gates), and the wasmtime host provider on both sockets generations — wasip3 and `std::net`/0.2 guests — with handle-address and profile-cipher-suite gates plus plain-TCP passthrough-delegation legs |
| `just interop` | cross-implementation, over real transports, fresh Ed25519 private PKI per run: the composed TLS component against OpenSSL and Go peers over TCP in both directions (including the close_notify-vs-truncation and reset scenarios), and the noq leg against quic-go over UDP in both directions |
| `just audit` | no AES table constants reachable in the release wasm artifact |
| `just bench` | non-gating: the performance battery (packet protection, handshakes, record-path and QUIC bulk; native vs wasm vs composed component) with provenance-stamped output |
| `just timing-lab` | the dudect-style statistical timing lab under wasmtime. Non-gating and deliberately outside `just check` (statistical; environment-sensitive; verdicts are per-runtime-version and per-microarchitecture) — a weekly scheduled workflow runs it, and timing-lab/README.md's detection limits govern how to read a verdict |

Two invariants are already fixed:

- **The algorithm profile is the primary artifact.** The component is its
  enforced delivery (no consumer algorithm-configuration surface), the
  Rust guest library its curated delivery. A change that lets a consumer
  reconfigure the profile through the component, or that lets library API
  shape accept class-D private key material, is a design regression, not a
  feature.
- **Class-D operations never run in the guest.** The timing-channel
  classification (classes A–D) is inherited from
  [`component-webcrypto`'s in-guest provider README](https://github.com/polymorph-components/polymorph-webcrypto/blob/main/rust/guest-provider/README.md)
  — read it before touching anything cryptographic. The endpoint's own
  CertificateVerify signature is the one class-D-shaped operation in TLS
  1.3; it is served by an Ed25519 (class B) identity key in-guest or by a
  world-imported signer, enforced structurally at composition time, never
  by configuration.

Before designing WIT or touching async/stream plumbing, consult
[`lann/wasm-component-starter`](https://github.com/lann/wasm-component-starter)
(especially `OUTLINE.md`) — treat it as a living knowledge base and re-read
it rather than relying on a cached summary.

## WIT doc comments

Every WIT comment is a doc comment: bindings generators project it into
library documentation, so its audience is the package's *consumers* — from
experienced cryptographic engineers to junior general software engineers —
not this repository's contributors.

- Package-wide contracts belong in a `wit/README.md`, not in doc comments:
  a doc comment states what is specific to its item and links to the
  README section by name for the rest. Never restate a shared contract in
  full at a use site; never let a package-wide contract live only inside
  one item's doc.
- Order within a doc comment: basic usage first; then the
  security-critical contracts (as a `Security:` bulleted block when there
  is more than one point); then other details. The highest-impact caveat
  must never sit mid-paragraph behind mechanics.
- Use Simplified Technical English as guidance: short sentences, active
  voice, one instruction per sentence, consistent terms.
- No repository-internal content on the package surface: doc comments must
  not name this repository's implementations, test harnesses, issues, or
  design history. Implementation-specific facts are phrased neutrally;
  design rationale goes to the README or the issue tracker.

## Check the rationale before implementing it

Requests arrive with a reason attached — this is inefficient, this leaks,
this type would make the mistake unrepresentable. The reason is a claim
about the code, and it can be false while the request still points at
something real. Establish that it holds before writing the change, and if
it does not, say so first.

What this guards against is silent repair: noticing the premise is wrong,
quietly designing around it, and shipping something that works. Working
code then reads as confirmation of reasoning that was never tested, and the
next decision builds on it. A contradiction turned up while researching is
a result to report, not an obstacle to route around.

Two claims usually need separating, because a request tends to fuse them:
what is wrong with the code now, and what the proposed remedy fixes. They
are often both true of *different* problems. A wrapper type that makes an
unsafe read impossible does not thereby remove a redundant copy — and
adopting it can preserve the copy untouched while appearing to answer the
complaint. Name which property the change actually buys.

## Code comments and docs

Code comments describe **what** something is or does, not the process by
which it was arrived at. Rationale like "we removed X because Y" belongs in
commit messages or PR descriptions, not in source files.

A comment defending the *presence* of ordinary code is the same mistake in
a subtler form. Conventional things — a `Debug` impl, a prefixed error
string, a derived trait, an attribute the API guidelines call for — need no
defence; explaining why one is there implies it is unusual and sends the
reader looking for a catch that is not there. Comment what a reader could
not predict: an invariant, a hazard, a deliberate departure from the
obvious choice, a constraint imposed from outside the file.

The giveaway is the shape of the sentence. "Without this, a consumer
cannot…", "otherwise a caller has no indication…", "this is not merely…"
are answers to an objection, and the place to answer an objection is where
it was raised — the pull request. "This holds because…", "X must be Y
since…" state what is true of the code as it stands, which is what survives
once the discussion is forgotten. If a comment would read oddly to someone
who never saw the change that introduced it, it is in the wrong place.

Guards are the exception that proves it. A test, a lockfile, an assertion
exists *because* of the failure it prevents, so saying what it catches
describes what it is — and reads the same to someone who never saw it
added.

Docs state invariants, not inventories. Never embed values a build or test
run computes — case counts, check counts, probe indexes. If a number
matters, a gate asserts it; if it doesn't, omit it.

## Sizing pull requests

Three factors decide how much lands in one PR. They pull in different
directions, so they bind in this order.

1. **Necessity.** Changes that cannot land separately without leaving
   `main` worse between them — a stated contract the tree violates, a fix
   that activates a latent defect elsewhere, a gate red until the
   counterpart arrives — go in one PR, whatever that does to its size.
   Name the co-dependence in the description; a reviewer who cannot see
   why the pieces are inseparable will reasonably ask for the split.

2. **Cohesion.** One decision per PR: the description should be a single
   ruling plus its consequences, however many files those touch. "And
   also" is the tell that two PRs are sharing a branch. Cohesion caps what
   a PR may contain — it never forces changes together. One decision whose
   consequences land safely apart is two PRs, not one.

3. **Review time.** Within what the first two allow, smaller is better:
   the budget being spent is a human's attention on the diff. The converse
   also holds and is not an exception — many *nearly identical* changes
   are one PR, not many, because near-identical diffs review sublinearly.
   The test is textual similarity of the diffs, not thematic similarity of
   the work — two subsystems getting "the same treatment" through
   different mechanisms are two PRs.

## Tracking open findings in GitHub issues

Open review findings and design decisions live in this repository's GitHub
issue tracker (`gh issue list`), not in a TODO file. Before starting work
that touches an area, search the open issues — some encode contract
decisions that the change should resolve, not work around.

Close issues through PRs. When a PR fully resolves an issue, put a standard
closing-keyword line (e.g. `Fixes #N`, `Closes #N`) in the PR description
so the merge closes it automatically and the cross-reference is recorded.
When a PR resolves only part of an issue, do not close it: tick the
resolved checklist items and leave a comment naming the PR, so the issue
always reflects what actually remains. File new issues for new findings
rather than adding TODO comments or files. Issue numbers are never reused,
so closed numbers remain stable references.

## Direction

The bootstrap issue set was the roadmap; the algorithm profile, WIT
package, component, guest library, QUIC compatibility layer,
delegated-signer bridge, interop harnesses, performance battery, and
timing lab have landed. See the open issues for what remains
(upstreaming, the tls-virt follow-ons).
