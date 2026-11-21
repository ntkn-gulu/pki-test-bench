# G16 PKI – Architecture

Build Your Own Certificate Authority: OpenSSL creates a 3-level chain (Root → Intermediate → localhost),
a local HTTPS server shows the "green lock", and a Test Bench serves one broken chain per port.

## Files

| Path | Role |
|---|---|
| `README.md` | How to reproduce the project from zero: requirements, quick start, demo phases 1–9, Firefox trust options, Test Bench + measured results, tools, security notes, troubleshooting, credits |
| `config/g16.cnf` | OpenSSL profiles: `v3_root_ca`, `v3_intermediate_ca` (pathlen:0 + Name Constraints), `v3_leaf`, plus the broken profiles used by the Test Bench |
| `scripts/00_env.sh` | Shared settings for every script (paths in `D:/...` form, `MSYS_NO_PATHCONV`, root-key password via `G16_ROOT_PASS` or prompt, coloured output, `run` = print then execute) |
| `scripts/01_root_ca.sh` … `03_leaf_localhost.sh` | Main flow: Root CA, Intermediate CA, localhost leaf + `fullchain.pem` |
| `scripts/04_verify.sh` | `openssl verify` of the main chain |
| `scripts/05_negative_certs.sh` | Certificates for ports 8444–8449, each wrong in exactly one way |
| `scripts/trust.sh` | Git Bash front end: `install` · `status` · `remove` · `reset [-DryRun] [-KeepPki] [-Force]` → runs the matching `.ps1` with `-ExecutionPolicy Bypass` for that one process |
| `scripts/trust_common.ps1` | Shared PowerShell helpers (dot-sourced): G16 certs in Windows stores (matched by `O=TDTU N05 Group 16`), Firefox profile checks, `Show-TrustStatus` |
| `scripts/install_root.ps1` | Phase 7: prints subject, SHA-256 and the SHA-1 thumbprint grouped like the Windows dialog, then `Import-Certificate` into `CurrentUser\Root` (no admin; Windows asks for confirmation) |
| `scripts/remove_root.ps1` | Phase 9: removes every G16 certificate from `CurrentUser`/`LocalMachine` `Root` and `CA` (LocalMachine only with admin), prints Firefox manual steps and the status |
| `scripts/trust_status.ps1` | Read-only status: Windows stores (Edge) + each Firefox profile |
| `scripts/reset_demo.ps1` | Clean state: stop `serve.py` on 8443–8449, remove G16 certs, delete Firefox exceptions for the bench ports (backup `cert_override.txt.g16bak`, only while Firefox is closed), delete `pki/` |
| `server/serve.py` | One process, 7 TLS servers on loopback (8443–8449). Holds `SCENARIOS` (port → chain, key, host, expected error, theory section) and `ROOT_CERT`. Routes: `/` dashboard, `/static/*`, `/api/info`, `/api/ping` |
| `server/dashboard/` | Read-only frontend (`index.html`, `style.css`, `app.js`, offline `vendor/` fonts + anime.js) |
| `tools/chain_check.py` | Library: `load_chain`, `describe` (cert → JSON), `validate` (the 6 steps of midterm §3.6, `mode="fixed"` or `"vulnerable"`) |
| `tools/verify_chain.py` | Command-line front end of `chain_check.validate` |
| `tests/run_matrix.py` | Test Results Matrix: asks 5 verifiers (openssl verify, Python `ssl`, curl/Schannel, chain_check fixed, chain_check vulnerable) about every Test Bench port; writes `tests/results.md` (report table, Edge/Firefox left as ☐) and `tests/results.json` (git-ignored, raw data + tool versions) |
| `tools/dev/cdp_shot.mjs` | Dev only: scripted screenshots of the dashboard through the DevTools Protocol |
| `pki/` | Generated keys and certificates (git-ignored) |

## Data flow

```
scripts/*.sh ──openssl──▶ pki/{root,intermediate,leaf,negative}/
                                   │
server/serve.py ◀──────────────────┘   loads chain + key per port (SCENARIOS)
   ├─ TLS handshake: sends leaf + intermediate, never the root
   ├─ /api/info  → describe() each cert + validate() against pki/root/rootCA.crt
   │               + protocol / cipher of the live socket
   └─ /api/ping  → reachable only if the browser accepted this port's certificate
                    (CORS * on this route only; CSP connect-src lists the 7 bench origins)

dashboard/app.js ── fetch /api/info ──▶ hero, readout, chain cards, 6 steps, Test Bench
                 ── fetch every /api/ping ──▶ live browser verdict per port

tools/verify_chain.py ──▶ chain from a live handshake (--port), from pki/ (--port --offline)
                          or from any PEM (--file) ──▶ chain_check.validate() ──▶ terminal report
```

## validate() – the 6 steps

1. **Path** – top of the chain is, or is issued by, a trusted root → else `AUTHORITY_INVALID`
2. **Signatures** – each certificate is signed by the next one
3. **Dates** – every certificate inside its validity period → else `DATE_INVALID`
4. **CA rules** – issuers are `CA:TRUE` with `keyCertSign`, pathlen respected (skipped in `vulnerable` mode = CVE-2011-0228); Name Constraints and leaf EKU are checked in both modes
5. **Name** – host must be in the SAN; CN is ignored → else `COMMON_NAME_INVALID`
6. **Revocation & CT** – always `skip` (private CA has no CRL/OCSP/CT)

## verify_chain.py interface

| Option | Meaning |
|---|---|
| `--port N` | Test Bench port; reads the chain the running server really sends (`SSLSocket.get_unverified_chain`, Python ≥ 3.13) |
| `--offline` | With `--port`: read the scenario's chain file from `pki/` instead |
| `--file PATH` | Any PEM chain, leaf first |
| `--host NAME` | Name checked in step 5 (default: scenario host, or `localhost`) |
| `--root PATH` | Trust anchors (default `pki/root/rootCA.crt`) |
| `--mode fixed\|vulnerable\|both` | `both` prints the two verifiers side by side and explains the steps where they differ |
| `--list` | Print the Test Bench scenarios |

Exit codes: `0` accepted, `1` rejected (`both` → follows `fixed`), `2` input error (missing file, server not reachable, unknown port).

## run_matrix.py

- Server: reuses a running `serve.py` when all 7 ports answer; otherwise starts the 7 servers in-process (`serve.start`) and shuts them down at the end. Some-but-not-all ports busy → setup error.
- Per verifier: `openssl verify -CAfile root -untrusted <rest of chain> -verify_hostname|-verify_ip` (from the chain files) · Python `ssl.create_default_context(cafile=root)` (live) · `curl --cacert root --ssl-no-revoke` (live; Schannel `0x…` error bits decoded to `CERT_TRUST_*` names) · `chain_check.validate` fixed / vulnerable on the chain fetched live.
- Each cell is compared with the browser expectation (accept only `id == "valid"`). `KNOWN_DEVIATIONS` lists the cells that differ on purpose (missing SAN accepted through CN fallback; leaf-as-CA accepted by the vulnerable verifier) with the reason printed in the report.
- Also records curl on the valid chain WITHOUT `--ssl-no-revoke` (revocation status unknown: private CA has no CRL/OCSP).
- Exit codes: `0` all cells match or are documented deviations, `1` unexpected or missing result, `2` setup error.

## Trust stores

| Client | Trust store | How G16 gets in |
|---|---|---|
| Edge, Chrome, curl (Schannel) | Windows `CurrentUser\Root` | `scripts/trust.sh install` |
| Firefox | Own NSS store (`cert9.db` per profile) **plus**, when `security.enterprise_roots.enabled` is on (Firefox default on Windows), the roots a user added to Windows | Automatic through Windows, or manual import (Settings → Certificates → Authorities → Import) when that option is off |

`Show-TrustStatus` detects a manual Firefox import by searching a slice of the root's public key in `cert9.db` (best effort; only the root contains its own key), reads the pref from `user.js`/`prefs.js`, and counts saved exceptions for the bench ports in `cert_override.txt`.

## Server rules

- Listens on `127.0.0.1` and `::1` only; TLS ≥ 1.2.
- Stops on **Enter** (mintty does not deliver Ctrl+C to Windows programs); all servers shut down in parallel. With no keyboard (stdin at EOF, e.g. started in the background) it runs until the process is killed.
- `allow_reuse_address = False`: a second `serve.py` cannot share the ports (on Windows `SO_REUSEADDR` would allow it); it prints "cannot listen" instead.
- No HSTS (it is per host, not per port, and would break the other localhost ports). CSP, `nosniff`, `no-referrer`, `no-store` on every response.

## Conventions

- PowerShell scripts use PowerShell's Verb-Noun function names and stay ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI).
- Python code follows PEP 8 (`snake_case` functions and variables, `PascalCase` classes, `UPPER_SNAKE_CASE` constants), matching the existing code base.
- Comments in English, simple words.
- Frontend never creates certificates; every certificate comes from OpenSSL on the terminal.
- Dashboard colours carry meaning only: green = valid, red = broken, blue = neutral emphasis; dashed outline = "certificate not present".
