# `polymorph:test`

Common infrastructure for testing WebAssembly components: a small WIT
contract between test **suites** (components that carry test cases) and test
**runners** (components or hosts that execute them), plus the tooling that
makes multi-target test operations tractable — inventory tracking, a
canonical results format, aggregation, and CI packaging.

Status: implemented and in active use (the M1 webcrypto-conformance
migration runs on it); the WIT contract below is frozen, and design
history lives in the [issues](../../issues). Downstream consumption is
rev-pinned git dependencies for now — cargo for the crates, npm for the
JS runner core (the root `package.json` exports `js/viewer`'s
source-only modules; its stability policy until registry publishing is
*pinned rev or nothing*). How the pieces layer
together is described in [ARCHITECTURE.md](ARCHITECTURE.md). Layout:
[`crates/`](crates/) (host-side Rust: core model, formats, results
schema, guest SDK, CLI, host-embed runner), [`components/`](components/)
(guest components: reference provider, composed CLI runner core, sample
and fixture suites), [`js/`](js/) (deltic runner leg + browser harness),
[`examples/compose/`](examples/compose/) (composition walkthrough),
[`examples/aggregate/`](examples/aggregate/) (cross-target aggregation
walkthrough), [`docs/findings.md`](docs/findings.md) (toolchain
findings log).

Quickstart (toolchain in [AGENTS.md](AGENTS.md); `just all` runs the
full verification matrix):

```sh
just build
cargo run -p component-test-runner --bin ct-runner -- \
  target/wasm32-wasip2/release/sample_suite.wasm
```

Writing a suite: [`components/sample-suite/README.md`](components/sample-suite/README.md).

## The contract

[`wit/tests.wit`](wit/tests.wit) defines two interfaces and two worlds:

```wit
interface test-context {
    resource context {
        diagnostic: async func(msg: string);
    }
}

interface tests {
    use test-context.{context};

    variant outcome { failed(string), skipped(string) }

    resource test-case {
        name: func() -> string;
        run: async func(ctx: borrow<context>) -> result<_, outcome>;
    }

    all: async func() -> list<test-case>;
}

world suite  { import test-context; export tests; }
world runner { import tests; }
```

A suite exports `tests` and imports `test-context`; a runner imports
`tests`. Because component instantiation is acyclic, a single component
cannot both provide `test-context` to the suite and consume the suite's
`tests`, so composition factors into two steps: **bundle** the suite with a
context provider (a small `wac` script re-exporting `tests`,
`test-context`, and `factory` from one shared provider instance), then
**`wac plug`** the bundle into a runner core. The linker is still the test
harness's registration step; the suite-facing step just has two nodes
inside it. Validated end-to-end; see [`examples/compose/`](examples/compose/).

## Case names

Names are the *only* case identity — lockfile keys, resume and selection
arguments, seed derivation, ratchet keys, results keys — so the grammar is
normative:

```
name    = segment *( "/" segment )          ; 1–256 bytes total
segment = 1*64 of [a-z 0-9 - _ .]           ; a segment is never "." or ".."
```

All segments except the last must additionally be valid WIT labels
(kebab-case: first word `[a-z][a-z0-9]*`; later words may also be
number-only, per the amended component-model label grammar — e.g.
`sha256-2048`). This makes
hierarchical prefixes project verbatim into nested instance names under
composition and introspection (no mangling layer for prefixes; the leaf —
where encoded parameters concentrate — keeps the full charset and needs
escaping in export-name contexts regardless). Strictness here is
deliberately maximal: loosening later is compatible, tightening never is.

- **Byte equality is the only equality.** Lowercase ASCII only: no Unicode
  normalization questions, no case-collisions on case-insensitive
  filesystems. SDKs normalize source-language names at declaration time;
  the lockfile reviews the result.
- The charset is simultaneously URL-path-safe, shell-safe, filesystem-safe
  (with `.`/`..` segments forbidden at the grammar), and free of glob
  metacharacters, so selection patterns cannot collide with literal names.
  Parameters encoded into ids (`16384`, `0x1a2b`, `v1.2`) fit; digit-first
  segments are legal.
- **Duplicate names are a hard error** — no go-style `#01`
  auto-disambiguation, which makes identity depend on registration order.
  Enforced at SDK build time, by aggregator validation (`run-error`), and
  by lockfile review. SDK manglers must re-check uniqueness *after*
  mangling, which can merge distinct source names.
- Hierarchy is prefix-grouping only; depth is unconstrained. Interop
  emitters map prefix → JUnit classname (`/` → `.`, documented-lossy).

## Feature tags

Capability gating lives *outside* the WIT contract, as static metadata
carried alongside the suite (custom section and/or lockfile, emitted by the
guest SDK from the same per-case declaration):

- A case tagged `<feature>` applies only to targets that have the feature.
- A case tagged `!<feature>` applies only to targets that *lack* it — these
  cases assert the feature is properly *declined* (not silently
  half-served).
- The applicability predicate: (every positive tag present) ∧ (no negative
  tag present). Untagged cases apply everywhere.
- Targets declare capability manifests (the features they are *missing*),
  keyed by implementation × environment.

A case that does not apply to a target is reported **`not-applicable`** by
the scheduler and never executed. `run` is feature-blind: no case ever
queries feature state.

This scheme is self-checking: a manifest that wrongly claims a feature is
missing causes the `!feature` decline case to fail against the supporting
target; a manifest that wrongly claims support causes the `<feature>` cases
to fail. Manifest errors always surface as red tests.

## Design commitments

In decreasing order of load-bearing:

- **The contract grows only on export sides.** The Component Model has no
  compatible growth path for anything in return position (no variant or
  record subtyping), but an exporter may compatibly export *more*. Growth
  therefore has exactly two channels: runner-side, as new methods on the
  `context` resource (old suites keep linking against newer providers);
  and suite-side, as new optional interfaces alongside `tests` (old
  runner cores ignore them; selection happens at composition time, since
  imports can never be optional — see the `concurrent-tests` sketch in
  the issues). This is also why `test-context` must ship in 0.1.0: a
  suite world's imports cannot be optional, so a growth surface added
  later would be the semver-major event it exists to avoid.
- **Enumeration is unconditional and deterministic.** `all()` takes no
  arguments and yields every case, in suite order, identically on every
  call and instance; names are stable. Lockfiles pin case names *and*
  feature tags (tag drift is coverage drift).
- **The returned `result` is the sole verdict.** `ok` is a pass; `ctx` is a
  sideband that never alters the verdict. This keeps the run protocol free
  of split-brain rules and maps onto every guest's native idiom:
  `Result<(), Outcome>` and `?` in Rust, thrown exceptions in JS and
  Python — the same shape pytest (`Failed`/`Skipped` raisables) and
  libtest-mimic (`Result<(), Failed>`) converged on.
- **Feature tags are metadata; `run` is feature-blind.** Gating is a set
  operation over static tags and the target manifest, computable by any
  layer without executing anything. Every feature named by a positive tag
  must be named by at least one negative-tagged (decline-asserting) case —
  enforced as a lockfile lint, so declining coverage is structural, not
  aspirational.
- **`skipped` is a claim, and exceptional.** A case returns
  `skipped(string)` only when a run-stable target fact turns out not to
  hold at run time (e.g. a declared hardware token is unavailable); the
  payload says what the case asserted instead. Gating knowable before the
  run belongs in tags. (Kept as an escape hatch with eyes open: the
  webcrypto conformance system needed zero runtime skips across ~8k
  self-contained cases, but platform-stored state — e.g. HSM-backed keys —
  breaks self-containment.)
- **State is not a feature.** Tags name facts a case cannot change.
  Cases needing platform state should provision–use–destroy within the
  case; a suite whose cases mutate facts other cases are gated on is
  broken regardless of the features model.
- **Structural features gate suites, not cases.** A feature that is a
  *world import* makes a suite uninstantiable on targets lacking it;
  neither the positive nor the decline case can run. Such features are
  consumed at the composition/workflow layers (per-world suite split,
  applicability derived from imports ∩ manifest, the structural claim
  policed by a composition-time gate), never expressed as case tags.
- **`run` never traps.** Expectation mismatches are `failed`; a trap is
  recorded as that case's failure and the instance treated as poisoned
  (mandatorily — a trapped instance is permanently unusable). A
  runner-imposed hang guard tripping is treated as a trap: cancellation is
  cooperative in the Component Model, so a hung case can only be abandoned
  with its instance. Guards should be longer than any SUT-internal
  operation timeout, so that genuine failures classify as `failed`
  outcomes and only true hangs trip the guard. Instance granularity is
  runner policy: a runner may instantiate per case (isolation, parallel
  replication, trivial trap containment) or share an instance across
  cases (cheap, but poisoning then costs the remainder — recover by
  re-instantiating and resuming by case name).
- **The outcome variant is closed.** Variant cases in return position have
  no compatible growth path, so `outcome` is designed never to need one:
  pass/fail/skip is the trichotomy every test framework has kept stable for
  decades, details ride the string payloads, and everything else grows on
  the `context` side.
- **Expected failure is not on the guest surface.** Capability gaps are
  target facts (a manifest); known-not-yet-passing cases are runner-side
  ratchets — and ratchets are two-sided: a listed loss no longer observed
  is also an error. Bugs get fixed, not declared.

Result-status vocabulary (for the future canonical results schema): an
executed case yields `pass | fail | skipped`; the scheduler adds
`not-applicable` (target facts, with the responsible tag as detail).
`deselected` is reserved for user-driven subset selection, distinct from
both.

Sequencing: runners run cases sequentially per suite instance — the
undeclared default, not a permanent restriction. Concurrent `run` calls
are safe at the ABI level (a sync-lifted suite serializes on its instance
lock) but not isolated — cases share the instance — and a suite's
concurrency tolerance is invisible to runners (lift style and backpressure
use are encapsulated), so it must be declared: the planned declaration is
a suite-side additive `concurrent-tests` interface (see issues), whose
presence is structural and type-checked. Runners wanting throughput today
replicate suite instances and partition cases (intra-instance concurrency
is cooperative-only — no parallelism).

To verify early (tracked in issues): the growth story assumes composition
tooling resolves a `test-context@0.1.x` import against a newer
semver-compatible export (wac/wasmtime semver-aware linking); and feature
tags in custom sections must survive componentization and composition
tooling. Test both before anything leans on them.

## Provenance

Synthesized from one lineage and one composition model:

- [`lann/wasi-test`](https://github.com/lann/wasi-test) — the composition
  model: suite exports, runner imports, the linker registers.
- The conformance-suite lineage:
  [`polymorph-components/polymorph-webrtc-datachannels`](https://github.com/polymorph-components/polymorph-webrtc-datachannels)'s
  suite (two-party, networked, timing-shaped; environment executors,
  expected-fail with unexpected-pass enforcement), from which
  [`polymorph-components/polymorph-webcrypto`](https://github.com/polymorph-components/polymorph-webcrypto)'s
  system forked and evolved (pure-compute, ~8000 cases; self-describing
  inventories, capability manifests, lockfiles, one results wire format,
  many adapters, one aggregator). The feature-tag scheme restructures
  webcrypto's declared-missing-features + decline-assertion design, with
  the decline branch factored out into paired `!feature` cases.

Because this is a single evolving practice, agreement between those
systems is weak evidence (possibly inertia) while their *divergences* are
strong evidence of what each domain forced. Independent support so far is
limited to external framework precedent (pytest, libtest-mimic, JUnit,
NUnit, Go), Component Model ABI constraints, and empirical toolchain
findings ([`docs/findings.md`](docs/findings.md)); evaluation against an unrelated-lineage corpus (e.g.
WPT, `go test`, LLVM lit) is tracked in the issues.

## Scope (tracked in issues)

- Guest SDKs: Rust (`suite!` macro) and JS (componentize-js) — including
  single-declaration emission of feature tags (static metadata + paired
  decline cases).
- The reference `test-context` provider component.
- Runners: `wasi:cli`, `wasi:http` (served UI + remote API), in-browser via
  deltic (runtime-linked), native embedding with a libtest-mimic frontend.
- Semver-compatible-linking verification for the `test-context` growth path;
  custom-section survival through composition tooling.
- Inventory lockfiles (names + tags) and the update workflow, including
  the decline-pair lint.
- Canonical results JSON, aggregator/validator, markdown matrix, static
  viewer.
- Interop emitters: JUnit XML, TAP, GitHub Actions annotations.
- Reusable GitHub Actions workflows.
- A `component-test` CLI wrapping composition, execution, and aggregation.
