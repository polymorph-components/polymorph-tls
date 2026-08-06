# timing-lab

A dudect-style statistical timing lab for the TLS/QUIC deliveries'
protocol-level secret-bearing surfaces: the `polymorph-tls` profile provider and
record machinery, the `polymorph-tls-quic` packet protection, and the
key-exchange and signing kernels beneath them, measured in-guest as a
wasm32-wasip2 command under `wasmtime`. It enforces constant-time
*execution* of the shipped code on a given runtime and machine; it is not
adversarial security testing.

```
just timing-lab                            # build + run under wasmtime
TIMING_LAB_SAMPLES=20000 just timing-lab   # trade runtime for sensitivity
TIMING_LAB_SEED=7 just timing-lab          # vary the schedule and inputs
TIMING_LAB_ISOLATE=1 just timing-lab       # add the investigation surfaces
just timing-lab-scheduled                  # as the scheduled job runs it
```

The lab also compiles and runs natively (`cargo run --release -p
timing-lab`), which measures the *native* backends (NEON, PMULL) rather
than the wasm ones — useful only as a comparison point and for the
`TIMING_LAB_DIT` knob below. The deliverable environment is wasmtime.

## Automation

`just timing-lab` is deliberately absent from `just check`: a statistical
experiment on a shared runner cannot gate pull requests without flaking
them. But an unautomated lab rots — its runtime behavior (the positive
controls' sensitivity to clock granularity, say) decays invisibly while
only its *compilation* is checked.

So it runs on its own cadence instead, weekly, from
`.github/workflows/timing-lab.yml`, and there a failure **fails the job**
rather than being swallowed by `continue-on-error`: a scheduled failure
notifies, and a job nobody is told about is the state this replaces. To
absorb the flakes that motivated keeping it out of CI,
`just timing-lab-scheduled` retries a diverging run once at 4× samples and
reports failure only if the divergence survives — a flake washes out at 4×
while a real leak's t grows. The report lands in the run's job summary
either way, together with the wasmtime version and CPU the verdicts are
valid for. `workflow_dispatch` takes a `samples` input for an on-demand
run at a different sensitivity.

## Relation to component-webcrypto's timing-lab

This is a parallel lab, not a shared harness. The statistic
(`src/stats.rs`: Welch's t over full and upper-percentile-cropped data,
max |t| > 10) is copied from
[component-webcrypto's timing-lab](https://github.com/polymorph-components/polymorph-webcrypto/tree/main/timing-lab)
so the two labs share one methodology, and the class hygiene (balanced
shuffled schedule, symmetric per-trial prep, discarded warm-up, batching)
follows its design. The harnesses differ because the subjects differ:

- The sibling measures through the composed component's WIT interface —
  its deliverable *is* the composed provider, and the stream plumbing is
  part of what a consumer calls. Measuring `polymorph:tls` the same way would
  be structurally uninformative: the component's surface is
  handshake-scale (open a connection, pump streams), so µs-scale record
  and packet operations would drown in stream plumbing, and the QUIC
  surfaces ship as a library (`polymorph-tls-quic`), not behind the component
  at all. This lab therefore measures the delivery crates in-guest at
  their protocol seams — the exact objects rustls and noq-proto invoke.
- The primitive coverage does **not** overlap the sibling's, despite both
  building on RustCrypto: the two repositories pin different RustCrypto
  generations (there: aes 0.8 / polyval 0.6 / curve25519-dalek 4 /
  ed25519-dalek 2 / p256 0.13; here: aes 0.9 / polyval 0.7 /
  curve25519-dalek 5 / ed25519-dalek 3 / p256 0.14 — the lockfiles are
  authoritative). Different code is different measurement subject matter,
  which is why this lab carries its own key-exchange and AEAD surfaces
  rather than deferring to the sibling's verdicts.

## Methodology

Per surface, the lab interleaves measurements of **two input classes
chosen so that only secret-dependent behavior could separate them**, then
compares the two timing distributions with Welch's t-test — over the full
data and over upper-percentile-cropped subsets (timing tails are heavy;
cropping the slowest samples exposes differences the tail would drown). A
surface leaks if max |t| over all crops exceeds 10, the reference dudect's
threshold for exactly this max-over-crops statistic (the single-test 4.5
would over-report).

Class design is the load-bearing choice, and three shapes recur:

- **Corrupted first vs last** (the rejection surfaces): the AEAD tag is
  corrupted at its first byte vs its last byte. Both calls fail and
  recompute the same MAC, so any timing difference isolates the tag
  **comparison** — the classic early-exit leak.
- **Fixed vs fresh-random data** (the seal surfaces): a fixed
  *random-valued* plaintext vs a fresh one, probing data-dependent cipher
  timing (a table-based GHASH, a value-dependent JIT lowering). The fixed
  buffer is deliberately not all-zeros: any constant detects
  value-dependent code paths, and an all-zero 16 KiB class additionally
  measures hardware value-dependence and degenerates GHASH (a zero
  accumulator keeps every multiply operand zero) — see "The hardware
  floor" below.
- **Fixed vs fresh-random secret** (the key surfaces): key-exchange
  scalars, identity keys, HKDF input secrets. The key-exchange fixed
  scalar has a single mid-position bit set: the canonical leak this shape
  targets — weight-proportional scalar-mult timing, a double-and-add
  regression — separates the class means by the weight difference times
  the per-bit cost, so the fixed class sits at the extreme of the
  distribution the random class draws from rather than near its mean.
  (X25519 clamping sets bit 254, so its fixed scalar measures at weight
  2; the P-256 scalar at weight 1.)

Every cryptographic setup is guarded by a published known answer (RFC 8032
TEST 1, RFC 7748 §6.1, Wycheproof, RFC 5869 TC1) or a
roundtrip-plus-corruption check, so a wrong key template or a broken rig
fails the run rather than timing something else.

Three properties of the sampling loop keep class from correlating with
anything but the input:

- **A balanced, shuffled schedule.** Class order is a shuffled permutation
  of equal counts, not a per-trial coin flip: a coin flip's random walk
  exhausts one class ~√n trials before the other, leaving the run's final
  samples all one class — precisely where end-of-run drift lives.
- **Symmetric per-trial work.** Every trial draws the fresh random fill
  and writes the same buffers whichever class it feeds, so the harness's
  own memory traffic — and the cache and write-back state it leaves for
  the timed window — is class-independent, and only the *values* differ.
- **Discarded warm-up.** Trials per class run before sampling begins, so
  one-off costs (code paths, caches, lazy allocations) land outside the
  data.

Probe lengths follow the signal, and the two kinds pull in opposite
directions. A tag comparison's early-exit signal is a fixed ~15-byte
difference no matter how long the message is, while the noise it competes
with — the MAC recomputation inside the timed window — grows with the
message; the rejection surfaces therefore use a short (64-byte) message.
Data-dependent cipher effects accumulate per block, so the seal surfaces
use a long (16 KiB) plaintext, the TLS 1.3 record ceiling. Surfaces whose
single call sits near the guest clock's resolution batch several calls per
timed sample (the `batch` column; `mean`/`sigma` describe the whole batch
window): the signal scales with the batch while per-sample clock noise
does not.

## Surfaces

| surface | classes | what it isolates |
| --- | --- | --- |
| `handshake/certificate-verify-sign` | fixed vs fresh Ed25519 identity key, fixed message | the provider signer rustls calls for the endpoint's own CertificateVerify — TLS 1.3's one class-D-shaped operation, served by a class-B Ed25519 key |
| `handshake/server` | fixed vs fresh server identity, full RPK handshake per trial | identity-key-dependent server processing time — the Brumley–Boneh shape (repeated handshakes under one long-term key, attacker-observable latency) |
| `key-schedule/hkdf-extract-expand` | fixed vs fresh input secret | the suite's HKDF-SHA256 — the machinery behind every key-schedule derivation and key update |
| `key-exchange/x25519`, `key-exchange/p256` | single-mid-bit vs fresh scalar, fixed peer | scalar-dependent control flow or memory access in the scalar multiplication. Crate-level (`x25519-dalek`, `p256`) by necessity: rustls draws ephemeral scalars internally, so there is no seam to inject through |
| `record/{suite}/open-reject` | tag corrupted first vs last | the record decrypter's tag comparison, through the same `Tls13AeadAlgorithm` objects rustls drives, keyed from a real handshake's extracted traffic secrets |
| `record/{suite}/seal` | fixed vs fresh 16 KiB plaintext | data-dependent cipher timing in the record encrypter (AES-CTR+GHASH / ChaCha20-Poly1305) |
| `packet/{suite}/open-reject`, `packet/{suite}/seal` | as the record surfaces | RFC 9001 packet protection, through `quic::Keys` — the `polymorph-tls-quic` delivery |
| `packet/{suite}/hp-mask` | fixed vs fresh 16-byte sample, fixed key | header-protection mask derivation — input-dependent timing of the raw cipher invocation (the table-based-AES shape the profile excludes by construction) |
| `token/aes-256-gcm/open-reject` | tag corrupted first vs last | the noq endpoint's retry/NEW_TOKEN AEAD — attacker-supplied tokens opened under a long-lived key on unauthenticated Initials |
| `error/record-reject` | tag corrupted first vs last | the full server rejection path — deframing, decrypt failure, alert state machine — through a live connection, fresh handshake per trial |

The `handshake/server` window times only server-side processing
(`read_tls` + `process_new_packets` + `write_tls`); the client runs
untimed between windows. Session tickets are disabled so the window is
the handshake proper.

## Controls

Every run is bracketed by in-guest controls, one per class shape and one
per signal scale — a positive control validates only the shape and scale
it uses:

- **`control/leaky-equal`** — a deliberate early-exit byte compare over
  4096 bytes, the *corrupted-first-vs-last* shape. MUST read as a leak;
  if it doesn't, the harness cannot see anything at this measurement
  distance and every other verdict is meaningless, so the run fails.
- **`control/leaky-tag-compare`** — the same leak at AEAD-tag scale
  (16 bytes), batched like the rejection surfaces: it calibrates
  detectability at exactly the signal size those surfaces' quiet verdicts
  need bounding against. Also MUST leak.
- **`control/data-dependent-work`** — a per-byte loop whose trip count is
  the byte's low nibble, the *fixed-vs-random* shape at seal scale. Also
  MUST leak. Without it, a quiet seal verdict cannot distinguish "the
  cipher has no data dependence" from "the harness cannot see data
  dependence here".
- **`control/subtle-ct-eq`** — `subtle::ConstantTimeEq`, expected quiet.

The positive controls establish *detectability*, not a sensitivity
threshold: they leak by orders of magnitude, so they show the harness
works, not how small a leak it would catch.

## Detection limits (read before trusting a "quiet")

- **A quiet verdict bounds, it does not prove.** Sensitivity is
  proportional to the secret-dependent work and inversely proportional to
  the noise inside the timed window. The reported `mean ns` and
  `sigma ns` are that measurement distance: a per-class difference well
  below `sigma / √samples` is invisible to that row. The `delta ns`
  column is the observed effect size (class 0 minus class 1, signed like
  t), which is what a LEAK verdict is actually claiming.
- **Verdicts hold per runtime version and per microarchitecture.** The
  lab times the code wasmtime's compiler emits for this machine; a
  wasmtime upgrade or different hardware invalidates previous readings.
  The scheduled job records both.
- **The Ed25519 fixed class cannot reach extreme weight.** Ed25519
  expands the seed through SHA-512 before the scalar multiplication, so
  no choosable seed yields an extreme-weight scalar; the sign and
  handshake surfaces measure a *distribution-typical* fixed key and are
  gross-regression tripwires, not weight probes. The key-exchange
  surfaces are the weight probes.
- **The handshake surface cannot see ephemeral-scalar dependence.** Both
  classes draw fresh ephemeral randomness; only the long-term identity
  differs. Ephemeral-scalar timing is exactly what the key-exchange
  surfaces isolate.
- **Statistical tests flake.** A LEAK on a real surface warrants
  investigation, starting with a rerun at higher `TIMING_LAB_SAMPLES` —
  not an immediate conclusion. The scheduled job automates exactly that
  rerun.

## The hardware floor

The statistic cannot tell *why* two classes' timings differ, and on some
hardware the machine itself distinguishes data values. On an Apple
Silicon host (Linux VM), with 16 KiB all-zero vs random buffers, this lab
measured order-1% timing differences in loops containing **no
cryptography and no data-dependent instructions** — and, natively, a
stable ~0.3% difference on the P-256 surface that vanishes when
PSTATE.DIT (ARMv8 FEAT_DIT, data-independent timing) is set. That is
operand-dependent hardware timing, not a code path: DIT suppresses it,
and no bytecode or JIT property can remove it. Wasm code cannot set DIT
— a guest has no PSTATE access and wasmtime does not set it either — so
under wasmtime on such hardware the floor is simply present.

Consequences for the lab's design and for reading its reports:

- **No real surface uses an all-zero bulk-data class** (the
  `data-dependent-work` control does, deliberately — its leak is by
  construction). The seal surfaces' fixed class is a fixed random-valued
  buffer: still dudect's fixed-vs-random design, still sensitive to
  value-dependent code paths, but not sitting on the zeros pathology.
- **`TIMING_LAB_ISOLATE=1`** adds investigation surfaces that
  characterize the floor directly: the AES-GCM seal split into its
  kernels (AES-CTR alone, GHASH alone), a GHASH probe at the all-zeros
  extreme, the seal's true fixed-value-vs-fresh-value GHASH structure,
  a no-crypto XOR sweep, and mask-prep variants of both AES seal
  surfaces (both classes write the work buffer through one code path, so
  only values differ). On hardware with value-dependent timing, expect
  the zeros probes to read as leaks under wasm — that is the floor being
  measured, and the run's exit code will say so.
- **`TIMING_LAB_DIT=1`** (native aarch64 runs only) sets PSTATE.DIT
  before sampling. A native leak that DIT suppresses is hardware
  operand-dependence; one that survives is a code path. This is the
  discriminator to reach for before filing a crate issue.
- **On such hardware, expect threshold crossings under wasm** — where DIT
  cannot be set — on surfaces whose fixed class is operand-extreme by
  design: the single-bit key-exchange scalars foremost (on the Apple
  host above, `key-exchange/p256` crossed in roughly one run in six at
  2000 samples/class and reliably at 20000), occasionally the
  header-protection masks. Such a verdict is the lab truthfully
  reporting a machine property, not a code defect; the native
  `TIMING_LAB_DIT=1` comparison is the discriminator. No corresponding
  floor is expected for these instruction mixes on the scheduled x86-64
  runners; the weekly runs are what establish that empirically.

## Deliberately absent

- **Retry integrity tags and reset tokens as *sign* surfaces** — the
  retry integrity key is a published constant, and a reset token's
  HMAC-input classes would vary no secret; neither has a
  secret-varying class to build.
- **Verification surfaces** (signature verify, exporter checks) — they
  process public inputs; RFC 8446 requires no secrecy of the outcome.
- **Success-vs-failure timing** — whether a record authenticated is
  public (the connection tears down); the secret-bearing component of
  rejection is the tag comparison, which the rejection surfaces probe
  directly with both classes failing.
- **An end-to-end pass through the composed `polymorph:tls` component** —
  structurally uninformative, as above: handshake-scale stream plumbing
  swamps µs-scale record signals, and the QUIC deliveries do not sit
  behind the component at all.

## Relation to the timing-channel classes

The repository inherits component-webcrypto's timing-channel
classification (classes A–D, argued from code shape — see
`rust/tls/README.md` and the in-guest provider README it cites). The lab
is the empirical companion: it can catch regressions in the
countermeasures (the fixsliced AES, the masked-multiply GHASH, `subtle`
comparisons, the class-B scalar multiplications) as they are actually
compiled by wasmtime on the measurement machine, and it can confirm the
positive claims are not obviously wrong. It cannot prove a negative, and
it does not measure what it cannot see: physical channels (power,
frequency, the hardware floor above) and remote-attacker statistics are
out of scope.
