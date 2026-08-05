#!/usr/bin/env bash
# Smoke test for the tls-virt-host prototype: the demo component runs
# under the custom wasmtime embedding, whose wasi:sockets provider
# tunnels suffix-opted connections through TLS.
#
# Two legs. The tunnel leg dials a `.tls-virt.alt` name against
# `openssl s_server -rev`: gates that the resolver returned a handle
# address (fd00::/8), the reversed echo verified with clean closes, and
# openssl saw exactly the profile's cipher suites (the host TLS runs the
# lann-tls configs, not a stock provider). The passthrough leg dials an
# unsuffixed name against a plain-TCP reverse echo: gates that
# delegation to wasmtime-wasi carries an entire connection.
set -euo pipefail
cd "$(dirname "$0")/../.."

work=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

log() { printf '\n=== %s\n' "$*"; }

HOST=experimental/tls-virt-host/target/debug/tls-virt-host
DEMO=target/wasm32-wasip2/debug/tls_virt_demo.wasm
TESTDATA=rust/quinn/tests/testdata

log "build"
cargo build -p tls-virt-demo --target wasm32-wasip2
(cd experimental/tls-virt-host && cargo build)

log "fixture PKI to PEM"
openssl x509 -inform der -in "$TESTDATA/leaf.der" -out "$work/leaf.pem"
openssl pkey -inform der -in "$TESTDATA/leaf-key.p8" -out "$work/leaf-key.pem"

log "tunnel leg: openssl s_server (reversed echo over TLS)"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
openssl s_server -accept "$port" -naccept 1 -rev -tls1_3 \
    -cert "$work/leaf.pem" -key "$work/leaf-key.pem" > "$work/s_server.log" 2>&1 &
for _ in $(seq 1 100); do grep -q ACCEPT "$work/s_server.log" && break; sleep 0.1; done

timeout 60 "$HOST" "$DEMO" localhost.tls-virt.alt "$port" tls-virt-host-smoke \
    | tee "$work/demo.log"
wait

grep -q 'resolved localhost.tls-virt.alt -> fd' "$work/demo.log"
grep -q 'reversed echo verified' "$work/demo.log"
grep -q 'Ciphersuite: TLS_' "$work/s_server.log"
# The offered suites are the profile's, verbatim: the tunnel runs the
# lann-tls configs.
grep -q 'Client cipher list: TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256' \
    "$work/s_server.log"

log "passthrough leg: plain-TCP reverse echo (no TLS anywhere)"
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
for _ in $(seq 1 100); do grep -q 'listening on port' "$work/plain.log" && break; sleep 0.1; done
port=$(grep -o 'listening on port [0-9]*' "$work/plain.log" | head -1); port=${port##* }

timeout 60 "$HOST" "$DEMO" localhost "$port" passthrough-smoke \
    | tee "$work/demo2.log"
wait

grep -q 'reversed echo verified' "$work/demo2.log"
# No handle address: the resolver passed the real addresses through.
! grep -q 'resolved localhost -> fd' "$work/demo2.log"

echo
echo "tls-virt-host smoke OK"
