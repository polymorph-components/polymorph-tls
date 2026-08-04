#!/usr/bin/env bash
# Shared setup for the interop rigs: a scratch dir with a fresh Ed25519
# PKI and the built Go peer, cleaned up (with any background peers) on
# exit. Source from a script that has already `cd`ed to the repo root.
set -euo pipefail

work=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

log() { printf '\n=== %s\n' "$*"; }

# Waits for "listening on port N" in the log file $1 and prints N.
wait_port() {
    local port
    for _ in $(seq 1 100); do
        if port=$(grep -o 'listening on port [0-9]*' "$1" 2>/dev/null | head -1) \
            && [ -n "$port" ]; then
            echo "${port##* }"
            return 0
        fi
        sleep 0.1
    done
    echo "peer never announced its port; log:" >&2
    cat "$1" >&2
    return 1
}

scripts/interop-pki.sh "$work" 2>/dev/null
peer=$work/peer
(cd scripts/interop/peer && go build -o "$peer" .)
