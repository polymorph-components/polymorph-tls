#!/usr/bin/env bash
# Runs the performance battery and emits a provenance-stamped markdown
# report on stdout. Non-gating: numbers hold for one machine, one
# toolchain, one runtime version — all recorded in the header. See
# bench/README.md for methodology and how to read the rows.
set -euo pipefail
cd "$(dirname "$0")/.."

WASM=target/wasm32-wasip2/release
SIMD_DIR=target/simd128

>&2 echo "building (native, wasm, wasm+simd128, composed)..."
cargo build --quiet --release -p tls-bench -p quic-native-bench
cargo build --quiet --release --target wasm32-wasip2 \
    -p tls-bench -p quic-loopback -p tls-component-bench -p polymorph-tls-component
RUSTFLAGS="-C target-feature=+simd128" cargo build --quiet --release \
    -p tls-bench --target wasm32-wasip2 --target-dir "$SIMD_DIR"
wac plug --plug "$WASM/polymorph_tls_component.wasm" "$WASM/tls_component_bench.wasm" \
    -o target/tls-component-bench-composed.wasm

cpu=$( (grep -m1 'model name' /proc/cpuinfo || lscpu | grep -m1 -E 'Model name|Vendor ID') 2>/dev/null | sed 's/.*: *//' )
cpu="${cpu:-unknown} ($(nproc) cpus)"
cat <<EOF
# TLS/QUIC performance measurements

Provenance (results are valid only for this combination):

- date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- host: $(uname -sm), $cpu
- commit: $(git rev-parse --short HEAD)$(git diff --quiet || echo " (dirty)")
- rustc: $(rustc -V)
- wasmtime: $(wasmtime --version)

Rows are \`bench,<name>,<detail>,<unit>,<median>,<min>,<max>\` over
batches (see bench/README.md for batch shapes and caveats).
EOF

section() { printf '\n## %s\n\n```\n' "$1"; }
end() { printf '```\n'; }

section "native (hardware AES and carryless multiply via runtime detection)"
target/release/tls-bench all
target/release/quic-native-bench 32
end

section "wasm32-wasip2 under Wasmtime (baseline features)"
wasmtime run "$WASM/tls-bench.wasm" all
wasmtime run -S inherit-network "$WASM/quic-loopback.wasm" bench 32
end

section "wasm32-wasip2 under Wasmtime (+simd128)"
wasmtime run "$SIMD_DIR/wasm32-wasip2/release/tls-bench.wasm" all
end

section "composed polymorph:tls component under Wasmtime (component-model async)"
wasmtime run -W component-model-async=y target/tls-component-bench-composed.wasm 8 20
end
