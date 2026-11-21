#!/usr/bin/env bash
# Phase 2 - Create the G16 Intermediate CA, signed by the Root CA (5 years, pathlen:0, Name Constraints)
source "$(dirname "$0")/00_env.sh"

mkdir -p "$INT_DIR"

c_title "Phase 2: G16 Intermediate CA"

c_title "2.1 Generate the intermediate private key (RSA 4096)"
run openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$INT_DIR/intermediate.key"

c_title "2.2 Create a Certificate Signing Request (CSR)"
run openssl req -new -key "$INT_DIR/intermediate.key" \
    -subj "$SUBJ_BASE/CN=G16 Intermediate CA" \
    -config "$CNF" -out "$INT_DIR/intermediate.csr"

c_title "2.3 The Root CA signs the CSR (profile v3_intermediate_ca, 1825 days)"
run openssl x509 -req -in "$INT_DIR/intermediate.csr" \
    -CA "$ROOT_DIR/rootCA.crt" -CAkey "$ROOT_DIR/rootCA.key" "${ROOT_PASS_IN[@]}" \
    -set_serial "0x$(openssl rand -hex 16)" -sha256 -days 1825 \
    -extfile "$CNF" -extensions v3_intermediate_ca \
    -out "$INT_DIR/intermediate.crt"

c_ok "Created $INT_DIR/intermediate.crt"
openssl x509 -in "$INT_DIR/intermediate.crt" -noout -subject -issuer -dates \
    -ext basicConstraints,nameConstraints
