#!/usr/bin/env bash
# TLS interop: the composed lann:tls component against independent
# implementations — OpenSSL (s_server/s_client) and Go (crypto/tls) —
# over real TCP through wasi:sockets, in both directions, under a fresh
# Ed25519 private PKI.
#
# The close scenarios are gates for the interface's close_notify
# contract: a peer that closes cleanly must surface as a clean TLS
# close, and a peer that skips close_notify (FIN or RST) must surface
# as truncation, never as end-of-data.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/interop-lib.sh

WASM=target/wasm32-wasip2/debug
COMPOSED=$WASM/tls-tcp-composed.wasm
RUN=(timeout 60 wasmtime run -W component-model-async=y -S p3 -S inherit-network)

wac plug --plug "$WASM/lann_tls_component.wasm" "$WASM/tls_tcp.wasm" -o "$COMPOSED"

# Runs the composed demo with the PKI directory preopened at /pki.
demo() { "${RUN[@]}" --dir "$work::/pki" "$COMPOSED" "$@"; }

log "our client -> openssl s_server (clean close, reversed echo)"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
openssl s_server -accept "$port" -naccept 1 -rev -tls1_3 \
    -cert "$work/leaf.pem" -key "$work/leaf-key.pem" \
    -alpn tls-interop/1 > "$work/s_server.log" 2>&1 &
for _ in $(seq 1 100); do grep -q ACCEPT "$work/s_server.log" && break; sleep 0.1; done
demo client 127.0.0.1 "$port" localhost /pki/ca.der interop-request clean tseuqer-poretni
wait

log "openssl s_client -> our server (clean close, echo)"
demo server 127.0.0.1 0 /pki/leaf.der /pki/leaf-key.p8 > "$work/our_server.log" 2>&1 &
server_job=$!
port=$(wait_port "$work/our_server.log")
{ printf 'openssl-to-lann\n'; sleep 2; } | timeout 30 openssl s_client \
    -connect "127.0.0.1:$port" -tls1_3 -alpn tls-interop/1 \
    -CAfile "$work/ca.pem" -verify_return_error -verify_hostname localhost \
    -servername localhost -quiet -no_ign_eof > "$work/s_client.log" 2>&1
grep -qx 'openssl-to-lann' "$work/s_client.log"
wait "$server_job"
grep -q 'tls receive: clean close_notify' "$work/our_server.log"
cat "$work/our_server.log"

log "Go tls-client -> our server (asserts our close_notify)"
demo server 127.0.0.1 0 /pki/leaf.der /pki/leaf-key.p8 > "$work/our_server2.log" 2>&1 &
server_job=$!
port=$(wait_port "$work/our_server2.log")
"$peer" tls-client -port "$port" -ca "$work/ca.pem" -payload go-to-lann
wait "$server_job"
cat "$work/our_server2.log"

go_server_scenario() {
    local close_mode=$1 expect=$2 payload=$3
    log "our client -> Go tls-server (-close $close_mode, expect $expect)"
    "$peer" tls-server -cert "$work/leaf.pem" -key "$work/leaf-key.pem" \
        -close "$close_mode" > "$work/go_server.log" 2>&1 &
    local peer_job=$!
    local port
    port=$(wait_port "$work/go_server.log")
    demo client 127.0.0.1 "$port" localhost /pki/ca.der "$payload" "$expect" \
        | tee "$work/our_client.log"
    wait "$peer_job"
}

go_server_scenario clean clean clean-close-please
go_server_scenario fin truncated skip-close-notify-please
grep -q 'tls receive error: transport closed without TLS close_notify' "$work/our_client.log"
go_server_scenario rst reset reset-please

echo
echo "tls interop OK"
