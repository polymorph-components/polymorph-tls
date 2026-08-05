# Run all checks.
check: fmt-check clippy test build-wasm

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace

build-wasm:
    cargo build --workspace --exclude tls-virt-wasmtime --target wasm32-wasip2

# All loopback smoke tests.
smoke: smoke-quic smoke-tls smoke-tls-delegated

# QUIC over wasi:sockets UDP under Wasmtime.
smoke-quic: build-wasm
    wasmtime run -S inherit-network target/wasm32-wasip2/debug/quic-loopback.wasm

# The composed lann:tls component (component-model async). The grep gate
# asserts the composition satisfied every lann:tls import.
smoke-tls: build-wasm
    wac plug --plug target/wasm32-wasip2/debug/lann_tls_component.wasm target/wasm32-wasip2/debug/tls_loopback.wasm -o target/wasm32-wasip2/debug/tls-composed.wasm
    ! wasm-tools component wit target/wasm32-wasip2/debug/tls-composed.wasm | grep -q 'import lann:tls/'
    wasmtime run -W component-model-async=y target/wasm32-wasip2/debug/tls-composed.wasm

# The tls-delegated world with the composed test signer. The grep gates
# assert the delegated artifact carries the signer import (the bridge is
# reachable, not stripped) and that composition satisfies everything.
smoke-tls-delegated:
    cargo build -p lann-tls-component --features delegated-signer -p test-signer -p tls-delegated-loopback --target wasm32-wasip2
    wasm-tools component wit target/wasm32-wasip2/debug/lann_tls_component.wasm | grep -q 'import lann:tls/signer'
    wac plug --plug target/wasm32-wasip2/debug/test_signer.wasm target/wasm32-wasip2/debug/lann_tls_component.wasm -o target/wasm32-wasip2/debug/tls-delegated-with-signer.wasm
    wac plug --plug target/wasm32-wasip2/debug/tls-delegated-with-signer.wasm target/wasm32-wasip2/debug/tls_delegated_loopback.wasm -o target/wasm32-wasip2/debug/tls-delegated-composed.wasm
    ! wasm-tools component wit target/wasm32-wasip2/debug/tls-delegated-composed.wasm | grep -q 'import lann:tls/'
    wasmtime run -W component-model-async=y target/wasm32-wasip2/debug/tls-delegated-composed.wasm

# The tls-delegated world over a lann:webcrypto provider: clones and
# builds the sibling repository at the revision pinned alongside the
# shim's vendored WIT. Heavier than `smoke`; run on demand.
smoke-tls-webcrypto:
    #!/usr/bin/env bash
    set -euo pipefail
    rev="$(cat examples/webcrypto-signer/wit/deps/lann-webcrypto/.pinned-rev)"
    checkout=target/webcrypto-src
    if [ ! -e "$checkout/.git" ]; then
        git clone --filter=blob:none https://github.com/lann/component-webcrypto "$checkout"
    fi
    git -C "$checkout" fetch -q origin "$rev"
    git -C "$checkout" checkout -q "$rev"
    # component-webcrypto's workspace expects a sibling checkout of
    # lann/component-test (a dev-layout path dependency of its
    # conformance crates; the guest-provider build itself does not use it).
    if [ ! -e target/component-test/.git ]; then
        git clone --filter=blob:none https://github.com/lann/component-test target/component-test
    fi
    (cd "$checkout" && cargo build --release -p lann-webcrypto-guest-provider --target wasm32-wasip2)
    cargo build -p lann-tls-component --features delegated-signer -p webcrypto-signer -p tls-delegated-loopback --target wasm32-wasip2
    wac plug --plug "$checkout/target/wasm32-wasip2/release/lann_webcrypto_guest_provider.wasm" target/wasm32-wasip2/debug/webcrypto_signer.wasm -o target/wasm32-wasip2/debug/webcrypto-signer-with-provider.wasm
    wac plug --plug target/wasm32-wasip2/debug/webcrypto-signer-with-provider.wasm target/wasm32-wasip2/debug/lann_tls_component.wasm -o target/wasm32-wasip2/debug/tls-delegated-webcrypto.wasm
    wac plug --plug target/wasm32-wasip2/debug/tls-delegated-webcrypto.wasm target/wasm32-wasip2/debug/tls_delegated_loopback.wasm -o target/wasm32-wasip2/debug/tls-delegated-webcrypto-composed.wasm
    ! wasm-tools component wit target/wasm32-wasip2/debug/tls-delegated-webcrypto-composed.wasm | grep -q 'import lann:'
    wasmtime run -W component-model-async=y target/wasm32-wasip2/debug/tls-delegated-webcrypto-composed.wasm

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

# The quinn leg against quic-go over wasi:sockets UDP.
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

# The timing lab's scheduled wrapper: one retry at 4x samples before
# reporting failure — a flake washes out at 4x while a real leak's t grows,
# so the retry separates them; shared runners make the retry mandatory
# rather than optional. Records the environment the verdicts are valid for
# (verdicts hold per runtime version and per microarchitecture; a wasmtime
# upgrade or a runner change invalidates previous quiet readings). Under
# GitHub Actions the report also lands in the job summary.
timing-lab-scheduled:
    #!/usr/bin/env bash
    set -uo pipefail
    samples="${TIMING_LAB_SAMPLES:-2000}"
    cpu=$(sed -n 's/^model name[^:]*: //p' /proc/cpuinfo | head -n1)
    [ -n "$cpu" ] || cpu="$(sed -n 's/^CPU implementer[^:]*: /implementer /p' /proc/cpuinfo | head -n1)"
    environment="$(wasmtime --version), $(uname -m), ${cpu:-unknown CPU}"
    echo "timing lab environment: ${environment}"
    run() { TIMING_LAB_SAMPLES="$1" just timing-lab 2>&1; }

    report=$(run "$samples"); status=$?
    printf '%s\n' "$report"
    if [ $status -ne 0 ]; then
        samples=$(( samples * 4 ))
        echo
        echo "timing lab: verdicts diverged; retrying at ${samples} samples/class before reporting failure."
        report=$(run "$samples"); status=$?
        printf '%s\n' "$report"
    fi

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### timing lab — ${samples} samples/class"
            echo
            echo "Environment: ${environment}"
            echo
            # The lab prints its report as a markdown table; lift it verbatim.
            printf '%s\n' "$report" | sed -n '/^| surface/,/^$/p'
            if [ $status -eq 0 ]; then
                echo "All surfaces matched expectations."
            else
                echo "**Surfaces diverged from expectation, and again on a retry at ${samples} samples/class.**"
                echo "A quiet positive control means the harness cannot detect leaks at this"
                echo "measurement distance; a LEAK on a real surface warrants investigation."
            fi
        } >> "$GITHUB_STEP_SUMMARY"
    fi
    exit $status
