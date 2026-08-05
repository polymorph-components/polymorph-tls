#!/usr/bin/env bash
# Smoke rig for the tls-virt-guest delivery: compose the demo app, the
# virtualizer, and the lann:tls component; run the composed component
# against `openssl s_server -rev` on localhost. The demo speaks plain
# TCP to a `.tls-virt.alt` name; every byte on the wire is TLS.
#
# Gates: the composition satisfies every lann:tls and virt:sockets
# import; the resolver returned a handle address (the fd00::/8 prefix),
# so the exchange went through the tunnel, not passthrough; openssl
# completed a TLS handshake; the demo verified the reversed echo and a
# clean close in both directions.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

log() { printf '\n=== %s\n' "$*"; }

WASM=target/wasm32-wasip2/debug
COMPOSED=$WASM/tls-virt-composed.wasm
TESTDATA=rust/quinn/tests/testdata

log "compose"
wac compose \
    --dep lann:tls-component="$WASM/lann_tls_component.wasm" \
    --dep lann:tls-virt-guest="$WASM/tls_virt_guest.wasm" \
    --dep lann:tls-virt-demo="$WASM/tls_virt_demo.wasm" \
    -o "$COMPOSED" rust/tls-virt-guest/compose.wac
! wasm-tools component wit "$COMPOSED" | grep -qE 'import (lann:tls|virt:sockets)/'

log "fixture PKI to PEM"
openssl x509 -inform der -in "$TESTDATA/leaf.der" -out "$work/leaf.pem"
openssl pkey -inform der -in "$TESTDATA/leaf-key.p8" -out "$work/leaf-key.pem"

log "openssl s_server (reversed echo)"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
openssl s_server -accept "$port" -naccept 1 -rev -tls1_3 \
    -cert "$work/leaf.pem" -key "$work/leaf-key.pem" > "$work/s_server.log" 2>&1 &
for _ in $(seq 1 100); do grep -q ACCEPT "$work/s_server.log" && break; sleep 0.1; done

log "composed demo dials localhost.tls-virt.alt:$port"
timeout 60 wasmtime run -W component-model-async=y -S p3 \
    -S inherit-network -S allow-ip-name-lookup=y \
    "$COMPOSED" localhost.tls-virt.alt "$port" tls-virt-guest-smoke | tee "$work/demo.log"
wait

grep -q 'resolved localhost.tls-virt.alt -> fd' "$work/demo.log"
grep -q 'reversed echo verified' "$work/demo.log"
grep -q 'Ciphersuite: TLS_' "$work/s_server.log"

echo
echo "tls-virt-guest smoke OK"
