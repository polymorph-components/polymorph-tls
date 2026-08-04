# AGENTS.md

Guidance for automated agents (and humans) working in this repository.

## What this repository is

`lann:tls`: a TLS 1.3 WIT package plus a pure-wasm implementation, designed
to serve QUIC over `wasi:sockets`. A sibling of
[`lann:webcrypto`](https://github.com/lann/component-webcrypto) and
[`lann:webrtc-datachannels`](https://github.com/lann/webrtc-datachannels),
deliberately mirroring their architecture — prefer clarity and correctness
over features. See [`README.md`](README.md) for the design.

The repository holds the `lann:tls` WIT package (`wit/`, with its README
of recorded rulings), the Rust deliveries, and their validation rigs. The
open requirements live in the GitHub issue tracker, and the README is the
design record.

## Layout

- `wit/` — the `lann:tls` package; `wit/README.md` carries the package
  contracts and recorded rulings (wasi-tls relationship, signer seam,
  worlds).
- `rust/profile` — the algorithm profile as data plus the identity types;
  the single policy source. Its README is the profile document.
- `rust/tls` — the curated core delivery: profile provider + TLS 1.3
  configs. Deliberately QUIC-free. Its README records the provider audit.
- `rust/quinn` — quinn compatibility: RFC 9001 packet protection,
  quinn-proto session glue, endpoint keys.
- `rust/quinn-wasi` — quinn-proto driver over `wasi:sockets` UDP; no TLS
  or profile dependency.
- `rust/component` — the `lann:tls` component (enforced delivery);
  wasm-only cdylib, `delegated-signer` feature selects the
  `tls-delegated` world.
- `examples/quic-loopback`, `examples/tls-loopback` — the smoke-test
  guests; `quic-loopback` also carries the QUIC interop endpoint modes.
- `examples/tls-tcp` — the real-transport demo guest: the composed
  component over `wasi:sockets` TCP; also the TLS interop endpoint.
- `scripts/` — audit helper and the interop harnesses (with their Go
  peer in `scripts/interop/peer`).

## Checks

| Recipe | Verifies |
| --- | --- |
| `just check` | fmt, clippy (all features), workspace tests (RFC 9001 vectors, profile/provider pinning, class-D key rejection), wasm build |
| `just smoke` | both loopback rigs under Wasmtime: QUIC over `wasi:sockets` UDP, and the wac-composed TLS component (component-model async) with its import-satisfaction gate |
| `just interop` | cross-implementation, over real transports, fresh Ed25519 private PKI per run: the composed TLS component against OpenSSL and Go peers over TCP in both directions (including the close_notify-vs-truncation and reset scenarios), and the quinn leg against quic-go over UDP in both directions |
| `just audit` | no AES table constants reachable in the release wasm artifact |

Two invariants are already fixed:

- **The algorithm profile is the primary artifact.** The component is its
  enforced delivery (no consumer algorithm-configuration surface), the
  Rust guest library its curated delivery. A change that lets a consumer
  reconfigure the profile through the component, or that lets library API
  shape accept class-D private key material, is a design regression, not a
  feature.
- **Class-D operations never run in the guest.** The timing-channel
  classification (classes A–D) is inherited from
  [`component-webcrypto`'s in-guest provider README](https://github.com/lann/component-webcrypto/blob/main/rust/guest-provider/README.md)
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
package, component, guest library, quinn compatibility layer, and
`wasi:sockets` adapter have landed. See the open issues for what remains
(timing verification, performance measurement, the delegated-signer
bridge, interop, upstreaming).
