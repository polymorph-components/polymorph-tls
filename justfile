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
