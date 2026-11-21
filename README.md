# G16 PKI – Build Your Own Certificate Authority

Course project for **Introduction to Information Security** (502049, HK1 2026, class N05, group 16)
Tạ Dưỡng (523H0131) · Nguyễn Thái Khánh Nam (523H0159) · Lecturer: Dr. Huỳnh Ngọc Tú

We use **OpenSSL as a Root CA**, build a 3-level chain of trust, issue a certificate for `localhost`,
install the root in the browser and show the **green lock** on a local HTTPS server. A **PKI Test Bench**
serves six broken chains on six more ports. Each one is wrong in exactly one way, so you can see which
validation step catches it in every client.

```
G16 Root CA (RSA 4096, self-signed, 10 y, CA:TRUE, key encrypted with AES-256)
 └─ G16 Intermediate CA (RSA 4096, 5 y, CA:TRUE, pathlen:0, Name Constraints: DNS:localhost, IP:127.0.0.1)
     └─ localhost (RSA 2048, 180 d, CA:FALSE, SAN: DNS:localhost, IP:127.0.0.1, EKU: serverAuth)
```

All certificates are created **with OpenSSL on the command line**. The web dashboard only reads and
displays the real certificates and the real TLS connection. It never creates anything.

---

## 1. Requirements

Tested on Windows 11 with:

| Tool | Version | Used for |
|---|---|---|
| Git for Windows (Git Bash) | 2.x, ships **OpenSSL 3.5.5** and curl 8.18 (Schannel) | all `scripts/*.sh`, `openssl`, `curl` |
| Python | **3.13** (launcher `py`) | server, `verify_chain.py`, `run_matrix.py` |
| Python package `cryptography` | 46.x | certificate parsing and the step-by-step validator |
| Windows PowerShell | 5.1 (built in) | installing and removing the root in the Windows trust store |
| Microsoft Edge / Mozilla Firefox | 157 / 159 | the green lock |

```bash
py -m pip install cryptography
```

Python 3.13 is needed because `verify_chain.py` reads the chain the server really sends with
`SSLSocket.get_unverified_chain()`. Nothing is downloaded at run time: fonts and anime.js are stored in
`server/dashboard/vendor/`, so the demo works offline.

---

## 2. Quick start

Run everything from **Git Bash** in the repo root:

```bash
cd pki-test-bench                # or wherever you cloned the repo

scripts/01_root_ca.sh            # Phase 1  Root CA        (asks for the root key password)
scripts/02_intermediate_ca.sh    # Phase 2  Intermediate CA (asks for the root key password)
scripts/03_leaf_localhost.sh     # Phase 3  localhost leaf + fullchain.pem
scripts/04_verify.sh             # Phase 4  openssl verify -> OK
scripts/05_negative_certs.sh     #          Test Bench certificates (ports 8444-8449)

py server/serve.py               # Phase 5  HTTPS on 8443-8449 (keep this window open, press Enter to stop)
```

Then, in a **second** Git Bash window:

```bash
scripts/trust.sh install         # Phase 7  add G16 Root CA to Windows (compare the thumbprint, click Yes)
scripts/trust.sh status          #          where is G16 trusted right now (Windows + Firefox)
py tests/run_matrix.py           #          Test Results Matrix for 5 non-browser verifiers
scripts/trust.sh remove          # Phase 9  remove the root again: the warning comes back
```

> **Root key password.** In the live demo, OpenSSL asks for it. For automated runs you can
> `export G16_ROOT_PASS=...` before scripts 01–02. Do not put the password in any file.

---

## 3. The demo, phase by phase

| Phase | What to do | What you should see |
|---|---|---|
| 1–3 | `scripts/01…03` | Every OpenSSL command is printed before it runs, then `subject / issuer / dates` and the key extensions |
| 4 | `scripts/04_verify.sh` | `localhost.crt: OK`, hostname and IP checks OK, the key matches the certificate |
| 5 | `py server/serve.py` | 7 servers listening on `127.0.0.1` and `::1` only |
| 6 | Open https://localhost:8443 **before** installing the root | Edge: `NET::ERR_CERT_AUTHORITY_INVALID` · Firefox: `SEC_ERROR_UNKNOWN_ISSUER` |
| 7 | `scripts/trust.sh install` (Edge) · manual import (Firefox, see below) | Windows "Security Warning" with the SHA-1 thumbprint printed by the script |
| 8 | Reload https://localhost:8443 | Lock icon; the certificate viewer shows G16 Root CA › G16 Intermediate CA › localhost; the dashboard shows the chain, TLS 1.3, cipher, SAN, fingerprints and the 6 validation steps |
| 9 | `scripts/trust.sh remove`, restart the browser | The warning is back: trust comes from the **trust store**, not from the server |

### Firefox has two ways to trust a root

Firefox keeps its **own** trust store (NSS, `cert9.db` in the profile). Since Firefox 120 on Windows it
also trusts roots that a user added to the Windows store. This is controlled by
**Settings › Privacy & Security › Certificates › "Allow Firefox to automatically trust third-party root
certificates you install"** (pref `security.enterprise_roots.enabled`, on by default).

Our demo turns this option **off** to show that Firefox's store is separate:

1. Untick the option and restart Firefox. https://localhost:8443 shows `SEC_ERROR_UNKNOWN_ISSUER`.
   Do **not** click "Accept the Risk and Continue": Firefox would remember that exception.
2. **View Certificates… › Authorities › Import…** › `pki\root\rootCA.crt` › tick **"Trust this CA to identify websites"**.
3. Reload: lock icon. `scripts/trust.sh status` now reports *"trusts G16 via imported in NSS store"*.

After the demo: delete G16 Root CA in the Authorities tab and tick the option again.

---

## 4. PKI Test Bench

`serve.py` runs one TLS server per port. Each port sends a different chain:

| Port | URL | What is wrong | Expected in a browser | Theory (midterm) |
|---|---|---|---|---|
| 8443 | https://localhost:8443 | nothing | lock icon | §3.4 Chain of Trust |
| 8444 | https://127.0.0.1:8444 | SAN only has `DNS:localhost`, opened by IP | `ERR_CERT_COMMON_NAME_INVALID` | §3.6 step 5 |
| 8445 | https://localhost:8445 | validity ended 2025-04-01 | `ERR_CERT_DATE_INVALID` | §3.6 step 3 |
| 8446 | https://localhost:8446 | no SAN, only `CN=localhost` | `ERR_CERT_COMMON_NAME_INVALID` | §3.3, §5.4 |
| 8447 | https://localhost:8447 | signed with the key of the **leaf** (CA:FALSE) | rejected | §5.4, CVE-2011-0228 |
| 8448 | https://localhost:8448 | SAN includes `evil.example`, outside the Name Constraints | rejected | §7.1, §7.3 |
| 8449 | https://localhost:8449 | self-signed, not from G16 | `ERR_CERT_AUTHORITY_INVALID` | §3.5 |

The dashboard's **Test Bench** section tests every port **from the browser you are using** (live browser
verdict) and has a **Copy as table** button for the report.

### Results (10/11/2026)

| Port | openssl verify | Python ssl | curl / Schannel | chain_check fixed | chain_check vulnerable | Edge 157 | Firefox 159 |
|---|---|---|---|---|---|---|---|
| 8443 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 8444 | ❌ IP address mismatch | ❌ | ❌ | ❌ step 5 | ❌ | ❌ | ❌ |
| 8445 | ❌ certificate has expired | ❌ | ❌ | ❌ step 3 | ❌ | ❌ | ❌ |
| 8446 | **✅ (CN fallback)** | **✅** | **✅** | ❌ step 5 | ❌ | ❌ | ❌ |
| 8447 | ❌ invalid CA certificate | ❌ | ❌ `INVALID_BASIC_CONSTRAINTS` | ❌ step 4 | **✅ (CVE-2011-0228)** | ❌ | ❌ |
| 8448 | ❌ permitted subtree violation | ❌ | ❌ `HAS_NOT_PERMITTED_NAME_CONSTRAINT` | ❌ step 4 | ❌ | ❌ | ❌ |
| 8449 | ❌ self-signed certificate | ❌ | ❌ untrusted root | ❌ step 1 | ❌ | ❌ | ❌ |

What this shows:
- **8446:** the same certificate is accepted by OpenSSL, Python and curl (they still fall back to the CN)
  but rejected by both browsers. Always test with the client you really target.
- **8447:** only the verifier that skips the Basic Constraints check accepts it. One missing check is
  enough to break the whole trust model.
- **8448:** Name Constraints are enforced by every client, so they are a strong defence for a private CA.

Regenerate the non-browser columns with `py tests/run_matrix.py`. It writes `tests/results.md` and `tests/results.json`.

---

## 5. Tools

### `tools/verify_chain.py` – the 6 validation steps, one by one

```bash
py tools/verify_chain.py --list                       # the 7 scenarios
py tools/verify_chain.py --port 8443                  # chain read from a live TLS handshake
py tools/verify_chain.py --port 8447 --mode both      # correct verifier vs. CVE-2011-0228
py tools/verify_chain.py --port 8445 --offline        # read pki/ instead (server not needed)
py tools/verify_chain.py --file pki/leaf/fullchain.pem --host localhost
```

The steps follow midterm §3.6: **1** path to a trusted root · **2** signatures · **3** dates ·
**4** CA rules (Basic Constraints, pathlen, Key Usage, Name Constraints, EKU) · **5** name in SAN (CN ignored) ·
**6** revocation & CT (skipped: a private CA has no CRL/OCSP/CT).
`--mode vulnerable` skips the Basic Constraints part of step 4.
Exit code: 0 = accepted, 1 = rejected, 2 = input error.

This validator is a **teaching tool** to make each step visible. Real software must use OpenSSL or the
platform verifier.

### `tests/run_matrix.py` – Test Results Matrix

Asks openssl, Python `ssl`, curl (Schannel), and `chain_check` fixed/vulnerable about every port. It
compares each result with what a browser does and lists the expected deviations with their reason. It
reuses a running `serve.py`, or starts the servers itself. Exit code 0 means every result is a browser
match or a documented deviation.

### `scripts/trust.sh` – Windows trust store

| Command | Effect |
|---|---|
| `scripts/trust.sh install` | Prints subject, SHA-256 and SHA-1 thumbprint, then imports the root into `CurrentUser\Root` (no admin needed) |
| `scripts/trust.sh status` | Read-only: G16 certificates in the Windows stores, and for each Firefox profile whether the root is imported, the "third-party roots" option, and saved exceptions |
| `scripts/trust.sh remove` | Removes **every** certificate with `O=TDTU N05 Group 16` from the Windows Root/CA stores (also roots from older runs) |
| `scripts/trust.sh reset -DryRun` | Shows what a reset would do |
| `scripts/trust.sh reset` | Clean state for a rehearsal: stops `serve.py`, removes the root, deletes Firefox exceptions for 8443–8449 (backup kept), deletes `pki/` (asks first) |

`trust.sh` runs PowerShell with `-ExecutionPolicy Bypass` for that one process only. The machine policy
is not changed.

---

## 6. Security notes

- `pki/` holds every private key and is in `.gitignore`. The repository never contains a key.
- The root key is encrypted (AES-256) and only needed for scripts 01–02. In a real CA it would stay
  **offline** (or in an HSM), and only the intermediate would sign day-to-day.
- `pathlen:0` and **Name Constraints** on the intermediate limit the damage if its key leaks: it cannot
  create sub-CAs, and it cannot issue for any name except `localhost` / `127.0.0.1`.
- The server listens on loopback only, accepts TLS ≥ 1.2, sends leaf + intermediate (never the root),
  and sets CSP, `X-Content-Type-Options`, `Referrer-Policy` and `Cache-Control`.
- **No HSTS** on purpose: HSTS is stored per host, not per port, so it would lock every `localhost` port
  and break the Test Bench.
- **Remove the root after the demo** (`scripts/trust.sh remove` + Firefox Authorities tab). A trusted
  root whose key can be copied is a risk for the whole machine (see the Superfish case in the report).

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `-subj` becomes a Windows path in Git Bash | `scripts/00_env.sh` sets `MSYS_NO_PATHCONV=1`. Use the scripts, or export it yourself |
| `cannot listen … WinError 10048` | Another `serve.py` is still running. Stop it (Enter in its window, or `scripts/trust.sh reset -DryRun` to find the PID) |
| Ctrl+C does not stop the server, and Git Bash says "processes are running" when you close it | mintty does not pass Ctrl+C to Windows programs. Press **Enter** in the server window. Closing the window also stops the server and changes nothing else |
| `.ps1 cannot be loaded because running scripts is disabled` | Use `scripts/trust.sh …`, or `powershell -ExecutionPolicy Bypass -File scripts\install_root.ps1` |
| Edge still shows the warning after `install` | Close Edge completely (also the tray icon / startup boost) and open it again |
| Firefox trusts G16 although you never imported it | The "trust third-party root certificates" option is on, so Firefox uses the Windows store |
| A Test Bench card says "! connects" | You clicked "Continue" on that port earlier. Restart the browser (Firefox: delete the exception, or run `scripts/trust.sh reset` with Firefox closed) |
| curl rejects even port 8443 with "revocation status is unknown" | Schannel checks revocation by default and our CA has no CRL/OCSP. Add `--ssl-no-revoke` |

---

## 8. Repository layout

```
config/g16.cnf          OpenSSL profiles (root, intermediate, leaf, and one profile per broken case)
scripts/                01–05 OpenSSL flow (Git Bash) · trust.sh + *.ps1 (Windows trust store)
server/serve.py         7 TLS servers + /api/info, /api/ping
server/dashboard/       read-only dashboard (offline fonts and anime.js in vendor/)
tools/chain_check.py    the 6-step validator (library)
tools/verify_chain.py   command-line front end of the validator
tests/run_matrix.py     Test Results Matrix
pki/                    generated keys and certificates (git-ignored)
```

`architecture.md` describes every file, the data flow and the interfaces in detail.

---

## 9. Credits

- [OpenSSL](https://www.openssl.org/) · Python [`ssl`](https://docs.python.org/3/library/ssl.html) and
  [`cryptography`](https://cryptography.io/)
- Dashboard: [anime.js](https://animejs.com/) (MIT), [Geist / Geist Mono](https://vercel.com/font) (SIL OFL 1.1)
- Main references: RFC 5280 (X.509 PKIX), RFC 8446 (TLS 1.3), RFC 6125 (service identity),
  CA/Browser Forum Baseline Requirements, CVE-2011-0228
- AI assistance: Claude (Anthropic) helped write the front-end code of the web dashboard (`server/dashboard/`)
  and double-checked the group's code (review for bugs and security mistakes).
  Every result in this README was measured on the demo laptop: the browser columns by the group, the other
  columns by `tests/run_matrix.py`.
