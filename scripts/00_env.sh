#!/usr/bin/env bash
# Common settings, loaded by every script with:  source "$(dirname "$0")/00_env.sh"

set -euo pipefail

# Git Bash would turn "-subj /C=VN/..." into a Windows path without this.
export MSYS_NO_PATHCONV=1

# pwd -W gives a Windows-style path (D:/g16-pki) that the native openssl.exe understands
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && (pwd -W 2>/dev/null || pwd))"
CNF="$REPO_DIR/config/g16.cnf"
PKI="$REPO_DIR/pki"
ROOT_DIR="$PKI/root"
INT_DIR="$PKI/intermediate"
LEAF_DIR="$PKI/leaf"
NEG_DIR="$PKI/negative"

SUBJ_BASE="/C=VN/O=TDTU N05 Group 16"

# Root key password.
#   - Live demo: leave G16_ROOT_PASS empty -> OpenSSL asks for the password.
#   - Automated test: export G16_ROOT_PASS=... before running.
if [[ -n "${G16_ROOT_PASS:-}" ]]; then
    ROOT_PASS_OUT=(-pass env:G16_ROOT_PASS)     # genpkey uses -pass
    ROOT_PASS_IN=(-passin env:G16_ROOT_PASS)
else
    ROOT_PASS_OUT=()
    ROOT_PASS_IN=()
fi

# Pretty output for the live demo
c_title() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
c_cmd()   { printf '\033[0;33m$ %s\033[0m\n' "$*"; }
c_ok()    { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
c_fail()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }

# Print a command, then run it (so the audience sees the real OpenSSL call)
run() { c_cmd "$*"; "$@"; }
