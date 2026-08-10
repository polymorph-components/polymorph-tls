# The orchestration surface: repo-wide recipes plus the GitHub Actions
# gha module, colocated with the workflows it drives.

mod conformance-ct "conformance/driver-ct/justfile"
# GitHub Actions plumbing: CI job entry points and workflow-only recipes.
mod gha ".github"

# List the available recipes.
default:
    @just --list

# The exact set of checks CI runs: each CI job runs exactly one gha:: job
# recipe. The timing lab is schedule-only (timing-lab.yml) and not part
# of ci.
ci: (gha::rust-checks) (gha::smoke) (gha::conformance-checks) (gha::interop)

# The fast pre-commit checks.
check: fmt-check clippy test build-wasm

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo clippy -p conformance-guest-ct --target wasm32-wasip2 -- -D warnings

test:
    cargo test --workspace

build-wasm:
    cargo build --workspace --exclude tls-virt-wasmtime --target wasm32-wasip2

# The cross-implementation conformance suite: the shared guest suite
# composed with each delivery, the aggregated matrix diffed against the
# committed one. See conformance/README.md.
conformance: conformance-ct::all conformance-ct::matrix-check

# QUIC over wasi:sockets UDP under Wasmtime.
smoke-quic: build-wasm
    wasmtime run -S inherit-network target/wasm32-wasip2/debug/quic-loopback.wasm

# Both tls-virt deliveries: the transparent-TLS sockets interposition
# against openssl over real TCP. Needs openssl and python3; not part of
# `smoke`.
smoke-tls-virt: smoke-tls-virt-guest smoke-tls-virt-wasmtime

# The composed guest virtualizer (tls-virt-guest).
smoke-tls-virt-guest: build-wasm
    scripts/smoke-tls-virt-guest.sh

# The wasmtime host provider (tls-virt-wasmtime), including its
# passthrough-delegation leg.
smoke-tls-virt-wasmtime: build-wasm
    cargo build -p tls-virt-wasmtime
    scripts/smoke-tls-virt-wasmtime.sh

# The performance battery: native, wasm, and composed-component rows
# with a provenance-stamped report on stdout. Non-gating; see
# bench/README.md. Capture with: just bench > bench/results/<name>.md
bench:
    scripts/bench.sh

# Binary audit: no table-based AES in the release wasm artifact.
audit:
    cargo build -p quic-loopback --target wasm32-wasip2 --release
    python3 scripts/audit-aes-tables.py target/wasm32-wasip2/release/quic-loopback.wasm

# Cross-implementation interop, both directions, over real transports.
interop: interop-tls interop-quic

# The composed component against OpenSSL and Go TLS peers over
# wasi:sockets TCP, including the close_notify-vs-truncation scenarios.
interop-tls: build-wasm
    scripts/interop-tls.sh

# The noq leg against quic-go over wasi:sockets UDP.
interop-quic: build-wasm
    scripts/interop-quic.sh

# The dudect-style timing lab: statistical timing tests of the deliveries'
# protocol-level secret-bearing surfaces, in-guest under wasmtime.
# Statistical and environment-sensitive by nature, so deliberately NOT part
# of `just check` — run it on a quiet machine, and read
# timing-lab/README.md for the methodology and detection limits before
# acting on a verdict. TIMING_LAB_SAMPLES trades runtime for sensitivity;
# TIMING_LAB_SEED varies the schedule and inputs; TIMING_LAB_ISOLATE=1 adds
# the investigation surfaces.
timing-lab:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p timing-lab --target wasm32-wasip2
    wasmtime --version
    args=(--env "TIMING_LAB_SAMPLES=${TIMING_LAB_SAMPLES:-2000}")
    [ -n "${TIMING_LAB_SEED:-}" ] && args+=(--env TIMING_LAB_SEED)
    [ -n "${TIMING_LAB_ISOLATE:-}" ] && args+=(--env TIMING_LAB_ISOLATE)
    wasmtime run "${args[@]}" target/wasm32-wasip2/release/timing-lab.wasm
