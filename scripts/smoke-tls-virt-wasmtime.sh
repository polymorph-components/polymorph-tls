#!/usr/bin/env bash
# Smoke rig for the tls-virt-wasmtime delivery: the demo components run
# under the wasmtime embedding, whose wasi:sockets providers (0.3 and
# 0.2) tunnel suffix-opted connections through TLS.
#
# Four legs, a tunnel and a passthrough leg per WASI version. Tunnel
# legs dial a `.tls-virt.alt` name against `openssl s_server -rev` and
# gate that the resolver returned a handle address (fd00::/8), the
# reversed echo verified with clean closes, and openssl saw exactly the
# profile's cipher suites (the host TLS runs the polymorph-tls configs, not a
# stock provider). Passthrough legs dial an unsuffixed name against a
# plain-TCP reverse echo and gate that delegation to wasmtime-wasi
# carries an entire connection. The 0.2 legs run a plain `std::net`
# Rust guest — Rust's std on wasm32-wasip2 sits on `wasi:sockets@0.2.x`.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

log() { printf '\n=== %s\n' "$*"; }

HOST=target/debug/tls-virt-wasmtime
DEMO_P3=target/wasm32-wasip2/debug/tls_virt_demo.wasm
DEMO_P2=target/wasm32-wasip2/debug/tls-virt-demo-p2.wasm
TESTDATA=rust/quic/tests/testdata

log "fixture PKI to PEM"
openssl x509 -inform der -in "$TESTDATA/leaf.der" -out "$work/leaf.pem"
openssl pkey -inform der -in "$TESTDATA/leaf-key.p8" -out "$work/leaf-key.pem"

# Runs a demo against a fresh `openssl s_server -rev` and applies the
# tunnel-leg gates.
tunnel_leg() {
    local demo=$1 payload=$2
    local port
    port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    : > "$work/s_server.log"
    openssl s_server -accept "$port" -naccept 1 -rev -tls1_3 \
        -cert "$work/leaf.pem" -key "$work/leaf-key.pem" > "$work/s_server.log" 2>&1 &
    for _ in $(seq 1 100); do grep -q ACCEPT "$work/s_server.log" && break; sleep 0.1; done

    timeout 60 "$HOST" "$demo" localhost.tls-virt.alt "$port" "$payload" \
        | tee "$work/demo.log"
    wait

    grep -q 'resolved localhost.tls-virt.alt -> fd' "$work/demo.log"
    grep -q 'reversed echo verified' "$work/demo.log"
    grep -q 'Ciphersuite: TLS_' "$work/s_server.log"
    # The offered suites are the profile's, verbatim: the tunnel runs
    # the polymorph-tls configs.
    grep -q 'Client cipher list: TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256' \
        "$work/s_server.log"
}

# Runs a demo against a fresh plain-TCP reverse echo and applies the
# passthrough-leg gates.
passthrough_leg() {
    local demo=$1 payload=$2
    : > "$work/plain.log"
    python3 - > "$work/plain.log" 2>&1 <<'EOF' &
import socket
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", 0))
s.listen(1)
print(f"listening on port {s.getsockname()[1]}", flush=True)
c, _ = s.accept()
data = b""
while True:
    b = c.recv(4096)
    if not b:
        break
    data += b
c.sendall(data.rstrip(b"\n")[::-1] + b"\n")
c.close()
EOF
    local port
    for _ in $(seq 1 100); do grep -q 'listening on port' "$work/plain.log" && break; sleep 0.1; done
    port=$(grep -o 'listening on port [0-9]*' "$work/plain.log" | head -1)
    port=${port##* }

    timeout 60 "$HOST" "$demo" localhost "$port" "$payload" | tee "$work/demo.log"
    wait

    grep -q 'reversed echo verified' "$work/demo.log"
    # No handle address: the resolver passed the real addresses through.
    ! grep -q 'resolved localhost -> fd' "$work/demo.log"
}

log "0.3 tunnel leg: openssl s_server (reversed echo over TLS)"
tunnel_leg "$DEMO_P3" p3-tunnel-smoke

log "0.3 passthrough leg: plain-TCP reverse echo (no TLS anywhere)"
passthrough_leg "$DEMO_P3" p3-passthrough-smoke

log "0.2 tunnel leg: std::net guest against openssl s_server"
tunnel_leg "$DEMO_P2" p2-tunnel-smoke

log "0.2 passthrough leg: std::net guest against plain-TCP reverse echo"
passthrough_leg "$DEMO_P2" p2-passthrough-smoke

echo
echo "tls-virt-wasmtime smoke OK"
