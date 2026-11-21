#!/usr/bin/env bash
# PKI Test Bench - create one "bad" certificate per test port (8444-8449).
# Each certificate is wrong in exactly ONE place, so each browser error has one cause.
source "$(dirname "$0")/00_env.sh"

mkdir -p "$NEG_DIR"

# new_key <name>  -> RSA 2048 key for a test server
new_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$NEG_DIR/$1.key" 2>/dev/null; }

# sign_by_intermediate <name> <profile> [extra x509 options...]
sign_by_intermediate() {
    local name=$1 profile=$2; shift 2
    openssl req -new -key "$NEG_DIR/$name.key" -subj "$SUBJ_BASE/CN=localhost" \
        -config "$CNF" -out "$NEG_DIR/$name.csr"
    run openssl x509 -req -in "$NEG_DIR/$name.csr" \
        -CA "$INT_DIR/intermediate.crt" -CAkey "$INT_DIR/intermediate.key" \
        -set_serial "0x$(openssl rand -hex 16)" -sha256 \
        -extfile "$CNF" -extensions "$profile" "$@" \
        -out "$NEG_DIR/$name.crt"
    # what the server sends: leaf + intermediate
    cat "$NEG_DIR/$name.crt" "$INT_DIR/intermediate.crt" > "$NEG_DIR/$name.fullchain.pem"
}

c_title "8444 wrong-name: valid only for DNS:localhost, opened as https://127.0.0.1:8444"
new_key wrong_name
sign_by_intermediate wrong_name v3_leaf_dns_only -days 180

c_title "8445 expired: validity period ended in 2025"
new_key expired
sign_by_intermediate expired v3_leaf -not_before 20250101000000Z -not_after 20250401000000Z

c_title "8446 no-san: only CN=localhost, no subjectAltName"
new_key no_san
sign_by_intermediate no_san v3_leaf_no_san -days 180

c_title "8447 leaf-as-ca: signed with the private key of localhost.crt (CA:FALSE)"
new_key leaf_as_ca
openssl req -new -key "$NEG_DIR/leaf_as_ca.key" -subj "$SUBJ_BASE/CN=localhost" \
    -config "$CNF" -out "$NEG_DIR/leaf_as_ca.csr"
run openssl x509 -req -in "$NEG_DIR/leaf_as_ca.csr" \
    -CA "$LEAF_DIR/localhost.crt" -CAkey "$LEAF_DIR/localhost.key" \
    -set_serial "0x$(openssl rand -hex 16)" -sha256 -days 30 \
    -extfile "$CNF" -extensions v3_leaf \
    -out "$NEG_DIR/leaf_as_ca.crt"
# chain sent by the server: fake leaf + real localhost leaf (acting as "CA") + intermediate
cat "$NEG_DIR/leaf_as_ca.crt" "$LEAF_DIR/localhost.crt" "$INT_DIR/intermediate.crt" \
    > "$NEG_DIR/leaf_as_ca.fullchain.pem"

c_title "8448 name-constraints: intermediate signs DNS:evil.example (outside permitted subtree)"
new_key nc_violation
sign_by_intermediate nc_violation v3_leaf_nc_violation -days 180

c_title "8449 self-signed: a leaf that does not belong to the G16 chain"
new_key self_signed
run openssl req -x509 -new -key "$NEG_DIR/self_signed.key" -sha256 -days 180 \
    -subj "/C=VN/O=Unknown Self-Signed/CN=localhost" \
    -config "$CNF" -extensions v3_self_signed -out "$NEG_DIR/self_signed.crt"
cp "$NEG_DIR/self_signed.crt" "$NEG_DIR/self_signed.fullchain.pem"

rm -f "$NEG_DIR"/*.csr

# -----------------------------------------------------------------------------
c_title "Quick check with openssl verify (every line below SHOULD fail)"
v() { openssl verify -CAfile "$ROOT_DIR/rootCA.crt" "$@" 2>&1 | grep -E "error|OK" | head -1; }
U="$INT_DIR/intermediate.crt"
echo "8444 wrong-name  : $(v -untrusted "$U" -verify_ip 127.0.0.1 "$NEG_DIR/wrong_name.crt")"
echo "8445 expired     : $(v -untrusted "$U" "$NEG_DIR/expired.crt")"
echo "8446 no-san      : $(v -untrusted "$U" -verify_hostname localhost "$NEG_DIR/no_san.crt")"
echo "                   (OpenSSL still falls back to the CN when there is no SAN -> OK here;"
echo "                    browsers ignore the CN and reject it -> see the Test Results Matrix)"
cat "$U" "$LEAF_DIR/localhost.crt" > "$NEG_DIR/.untrusted_8447.pem"
echo "8447 leaf-as-ca  : $(v -untrusted "$NEG_DIR/.untrusted_8447.pem" "$NEG_DIR/leaf_as_ca.crt")"
echo "8448 name-constr : $(v -untrusted "$U" "$NEG_DIR/nc_violation.crt")"
echo "8449 self-signed : $(v "$NEG_DIR/self_signed.crt")"
rm -f "$NEG_DIR/.untrusted_8447.pem"
