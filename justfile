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
    cargo build --workspace --target wasm32-wasip2

# Both loopback smoke tests.
smoke: smoke-quic smoke-tls

# QUIC over wasi:sockets UDP under Wasmtime.
smoke-quic: build-wasm
    wasmtime run -S inherit-network target/wasm32-wasip2/debug/quic-loopback.wasm

# The composed lann:tls component (component-model async). The grep gate
# asserts the composition satisfied every lann:tls import.
smoke-tls: build-wasm
    wac plug --plug target/wasm32-wasip2/debug/lann_tls_component.wasm target/wasm32-wasip2/debug/tls_loopback.wasm -o target/wasm32-wasip2/debug/tls-composed.wasm
    ! wasm-tools component wit target/wasm32-wasip2/debug/tls-composed.wasm | grep -q 'import lann:tls/'
    wasmtime run -W component-model-async=y target/wasm32-wasip2/debug/tls-composed.wasm

# Binary audit: no table-based AES in the release wasm artifact.
audit:
    cargo build -p quic-loopback --target wasm32-wasip2 --release
    python3 scripts/audit-aes-tables.py target/wasm32-wasip2/release/quic-loopback.wasm
