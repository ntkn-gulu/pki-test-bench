#!/usr/bin/env bash
# Phase 3 - Create the leaf certificate for localhost, signed by the Intermediate CA
source "$(dirname "$0")/00_env.sh"

mkdir -p "$LEAF_DIR"

c_title "Phase 3: Leaf certificate for localhost"

c_title "3.1 Generate the server private key (RSA 2048)"
run openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LEAF_DIR/localhost.key"

c_title "3.2 Create the CSR"
run openssl req -new -key "$LEAF_DIR/localhost.key" \
    -subj "$SUBJ_BASE/CN=localhost" \
    -config "$CNF" -out "$LEAF_DIR/localhost.csr"

c_title "3.3 The Intermediate CA signs it (profile v3_leaf, 180 days)"
run openssl x509 -req -in "$LEAF_DIR/localhost.csr" \
    -CA "$INT_DIR/intermediate.crt" -CAkey "$INT_DIR/intermediate.key" \
    -set_serial "0x$(openssl rand -hex 16)" -sha256 -days 180 \
    -extfile "$CNF" -extensions v3_leaf \
    -out "$LEAF_DIR/localhost.crt"

c_title "3.4 Build fullchain.pem = leaf + intermediate (the root is NOT sent)"
cat "$LEAF_DIR/localhost.crt" "$INT_DIR/intermediate.crt" > "$LEAF_DIR/fullchain.pem"
c_cmd "cat localhost.crt intermediate.crt > fullchain.pem"

c_ok "Created $LEAF_DIR/localhost.crt and fullchain.pem"
openssl x509 -in "$LEAF_DIR/localhost.crt" -noout -subject -issuer -dates \
    -ext basicConstraints,subjectAltName,extendedKeyUsage
