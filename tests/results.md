# Test Results Matrix

Measured 2026-11-20 14:11 +0700 by `tests/run_matrix.py`. ✅ = accepted · ❌ = rejected (reason).

| Port | Scenario | Expected (browser) | `openssl verify` | `Python ssl` | `curl / Schannel` | `chain_check fixed` | `chain_check vulnerable` | Edge | Firefox |
|---|---|---|---|---|---|---|---|---|---|
| 8443 | Valid chain | ✅ lock | ✅ OK | ✅ TLSv1.3 | ✅ OK | ✅ OK | ✅ OK | ☐ | ☐ |
| 8444 | Wrong name | ❌ NET::ERR_CERT_COMMON_NAME_INVALID | ❌ IP address mismatch | ❌ IP address mismatch | ❌ peer verification failed | ❌ Step 5 Name | ❌ Step 5 Name | ☐ | ☐ |
| 8445 | Expired | ❌ NET::ERR_CERT_DATE_INVALID | ❌ certificate has expired | ❌ certificate has expired | ❌ not time valid | ❌ Step 3 Dates | ❌ Step 3 Dates | ☐ | ☐ |
| 8446 | Missing SAN | ❌ NET::ERR_CERT_COMMON_NAME_INVALID | **✅ OK** | **✅ TLSv1.3** | **✅ OK** | ❌ Step 5 Name | ❌ Step 5 Name | ☐ | ☐ |
| 8447 | Leaf used as a CA | ❌ Rejected (CA rules) | ❌ invalid CA certificate | ❌ invalid CA certificate | ❌ IS_NOT_VALID_FOR_USAGE + INVALID_BASIC_CONSTRAINTS | ❌ Step 4 CA rules | **✅ OK** | ☐ | ☐ |
| 8448 | Name Constraints | ❌ Rejected (CA rules) | ❌ permitted subtree violation | ❌ permitted subtree violation | ❌ HAS_NOT_PERMITTED_NAME_CONSTRAINT | ❌ Step 4 CA rules | ❌ Step 4 CA rules | ☐ | ☐ |
| 8449 | Unknown issuer | ❌ NET::ERR_CERT_AUTHORITY_INVALID | ❌ self-signed certificate | ❌ self-signed certificate | ❌ untrusted root | ❌ Step 1 Path | ❌ Step 1 Path | ☐ | ☐ |

**Bold** = differs from a browser on purpose (documented deviation):

- 8446 · `openssl verify`: falls back to the CN when there is no SAN; browsers ignore the CN (§3.3)
- 8446 · `Python ssl`: default context still has hostname_checks_common_name = True (CN fallback)
- 8446 · `curl / Schannel`: the Schannel backend name check also falls back to the CN when the SAN is missing
- 8447 · `chain_check vulnerable`: Basic Constraints not checked: a CA:FALSE leaf can sign certificates (CVE-2011-0228, §5.4)

curl on Windows uses Schannel, which checks revocation by default. Our private CA has no CRL/OCSP, so the curl column uses `--ssl-no-revoke`. Without it, the valid chain gives: ❌ the revocation status is unknown.

Tool versions:

- openssl: OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
- python: Python 3.13.9 · OpenSSL 3.0.18 30 Sep 2025
- curl: curl 8.18.0 (x86_64-w64-mingw32) libcurl/8.18.0 Schannel zlib/1.3.1 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 WinLDAP
- os: nt win32
