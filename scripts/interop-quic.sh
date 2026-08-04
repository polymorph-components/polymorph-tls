#!/usr/bin/env bash
# QUIC interop: the quinn leg (quinn-proto with the profile's TLS 1.3,
# driven over wasi:sockets UDP) against an independent QUIC stack
# (quic-go), in both directions, under a fresh Ed25519 private PKI.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/interop-lib.sh

WASM=target/wasm32-wasip2/debug/quic-loopback.wasm
RUN=(timeout 60 wasmtime run -S inherit-network)

log "our client -> quic-go server"
"$peer" quic-server -cert "$work/leaf.pem" -key "$work/leaf-key.pem" \
    > "$work/go_server.log" 2>&1 &
peer_job=$!
port=$(wait_port "$work/go_server.log")
"${RUN[@]}" --dir "$work::/pki" "$WASM" client 127.0.0.1 "$port" localhost /pki/ca.der \
    quinn-to-quic-go
wait "$peer_job"
cat "$work/go_server.log"

log "quic-go client -> our server"
"${RUN[@]}" --dir "$work::/pki" "$WASM" server 127.0.0.1 0 /pki/leaf.der /pki/leaf-key.p8 \
    > "$work/our_server.log" 2>&1 &
server_job=$!
port=$(wait_port "$work/our_server.log")
"$peer" quic-client -port "$port" -ca "$work/ca.pem" -payload quic-go-to-quinn
wait "$server_job"
cat "$work/our_server.log"

echo
echo "quic interop OK"
