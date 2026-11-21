#!/usr/bin/env bash
# Phase 4 - Check the chain with OpenSSL (before touching any browser)
source "$(dirname "$0")/00_env.sh"

c_title "Phase 4: Verify the Chain of Trust"

c_title "4.1 Verify leaf -> intermediate -> root (root given as the only trust anchor)"
run openssl verify -show_chain -CAfile "$ROOT_DIR/rootCA.crt" \
    -untrusted "$INT_DIR/intermediate.crt" "$LEAF_DIR/localhost.crt"

c_title "4.2 Check that the leaf is valid for the name 'localhost' and IP 127.0.0.1"
run openssl verify -CAfile "$ROOT_DIR/rootCA.crt" -untrusted "$INT_DIR/intermediate.crt" \
    -verify_hostname localhost "$LEAF_DIR/localhost.crt"
run openssl verify -CAfile "$ROOT_DIR/rootCA.crt" -untrusted "$INT_DIR/intermediate.crt" \
    -verify_ip 127.0.0.1 "$LEAF_DIR/localhost.crt"

c_title "4.3 Check that the server key matches the leaf certificate"
leaf_pub=$(openssl x509 -in "$LEAF_DIR/localhost.crt" -noout -pubkey | openssl sha256)
key_pub=$(openssl pkey -in "$LEAF_DIR/localhost.key" -pubout | openssl sha256)
if [[ "$leaf_pub" == "$key_pub" ]]; then
    c_ok "localhost.key matches localhost.crt"
else
    c_fail "localhost.key does NOT match localhost.crt"; exit 1
fi
