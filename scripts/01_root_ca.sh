#!/usr/bin/env bash
# Phase 1 - Create the G16 Root CA (self-signed, 10 years, RSA 4096, password-protected key)
source "$(dirname "$0")/00_env.sh"

mkdir -p "$ROOT_DIR"

c_title "Phase 1: G16 Root CA"

c_title "1.1 Generate the root private key (RSA 4096, encrypted with AES-256)"
run openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes-256-cbc \
    "${ROOT_PASS_OUT[@]}" -out "$ROOT_DIR/rootCA.key"

c_title "1.2 Self-sign the root certificate (profile v3_root_ca, 3650 days)"
run openssl req -x509 -new -key "$ROOT_DIR/rootCA.key" "${ROOT_PASS_IN[@]}" \
    -sha256 -days 3650 \
    -subj "$SUBJ_BASE/CN=G16 Root CA" \
    -config "$CNF" -extensions v3_root_ca \
    -out "$ROOT_DIR/rootCA.crt"

c_ok "Created $ROOT_DIR/rootCA.crt"
openssl x509 -in "$ROOT_DIR/rootCA.crt" -noout -subject -issuer -dates -fingerprint -sha256
