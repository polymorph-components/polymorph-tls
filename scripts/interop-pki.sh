#!/usr/bin/env bash
# Generates a throwaway Ed25519 private PKI for the interop rigs: a CA
# and a "localhost" server leaf, in the PEM forms the native peers load
# and the DER forms the guests load.
set -euo pipefail

out=${1:?usage: interop-pki.sh <output-dir>}
mkdir -p "$out"

openssl genpkey -algorithm ed25519 -out "$out/ca-key.pem"
openssl req -new -x509 -key "$out/ca-key.pem" -subj "/CN=polymorph:tls interop CA" \
    -addext basicConstraints=critical,CA:TRUE -days 7 -out "$out/ca.pem"

openssl genpkey -algorithm ed25519 -out "$out/leaf-key.pem"
openssl req -new -key "$out/leaf-key.pem" -subj "/CN=localhost" -out "$out/leaf.csr"
openssl x509 -req -in "$out/leaf.csr" -CA "$out/ca.pem" -CAkey "$out/ca-key.pem" \
    -CAcreateserial -days 7 \
    -extfile <(printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n') \
    -out "$out/leaf.pem" 2>/dev/null

openssl x509 -in "$out/ca.pem" -outform DER -out "$out/ca.der"
openssl x509 -in "$out/leaf.pem" -outform DER -out "$out/leaf.der"
openssl pkcs8 -topk8 -nocrypt -in "$out/leaf-key.pem" -outform DER -out "$out/leaf-key.p8"
