"""
run_matrix.py - Test Results Matrix for the PKI Test Bench.

For every Test Bench port (8443-8449) it asks five different verifiers whether
they accept the certificate chain, and records the exact reason when they refuse:

    openssl     openssl verify -CAfile rootCA.crt -untrusted <rest of chain> -verify_hostname/-verify_ip
    python      Python ssl, default context (ssl.create_default_context(cafile=rootCA.crt))
    curl        curl --cacert rootCA.crt --ssl-no-revoke  (Windows: Schannel = the OS verifier)
    fixed       tools/chain_check.py, all 6 steps
    vulnerable  tools/chain_check.py without the Basic Constraints check (CVE-2011-0228)

The live columns (python, curl, fixed, vulnerable) talk to the real server. If
serve.py is not running, this script starts the 7 servers itself and stops them
at the end. The browser columns (Edge, Firefox) cannot be automated honestly:
use "Copy as table" on the dashboard Test Bench and paste them into the report.

Outputs:
    terminal table
    tests/results.md    Markdown table for the report (Edge/Firefox columns left as ☐)
    tests/results.json  every raw result + tool versions

Run (from the repo root):  py tests/run_matrix.py
Exit code: 0 = every result is the browser expectation or a documented deviation,
           1 = something unexpected happened (see the table), 2 = setup error.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "server"))
import serve                                                     # noqa: E402
from chain_check import load_chain, validate                     # noqa: E402
from verify_chain import fetch_chain                             # noqa: E402

ROOT_CERT = serve.ROOT_CERT
COLUMNS = ["openssl", "python", "curl", "fixed", "vulnerable"]
COLUMN_TITLES = {
    "openssl": "openssl verify",
    "python": "Python ssl",
    "curl": "curl / Schannel",
    "fixed": "chain_check fixed",
    "vulnerable": "chain_check vulnerable",
}

# Cells where a verifier is EXPECTED to disagree with a browser. Each one is a
# finding for the report, not a bug. Key = (port, column).
KNOWN_DEVIATIONS = {
    (8446, "openssl"): "falls back to the CN when there is no SAN; browsers ignore the CN (§3.3)",
    (8446, "python"): "default context still has hostname_checks_common_name = True (CN fallback)",
    (8446, "curl"): "the Schannel backend name check also falls back to the CN when the SAN is missing",
    (8447, "vulnerable"): "Basic Constraints not checked: a CA:FALSE leaf can sign certificates (CVE-2011-0228, §5.4)",
}


# --------------------------------------------------------------------------- #
#  Terminal colours (off when piped, or when NO_COLOR is set)
# --------------------------------------------------------------------------- #
COLOR_ON = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR_ON else text


# --------------------------------------------------------------------------- #
#  Finding the tools
# --------------------------------------------------------------------------- #
def find_tool(name: str, fallbacks: list[str]) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for path in fallbacks:
        if Path(path).is_file():
            return path
    return None


OPENSSL = find_tool("openssl", ["C:/Program Files/Git/mingw64/bin/openssl.exe",
                                "C:/Program Files/Git/usr/bin/openssl.exe"])
CURL = find_tool("curl", ["C:/Program Files/Git/mingw64/bin/curl.exe", "C:/Windows/System32/curl.exe"])


def first_line(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return "?"


def tool_versions() -> dict:
    return {
        "openssl": first_line([OPENSSL, "version"]) if OPENSSL else "not found",
        "python": f"Python {sys.version.split()[0]} · {ssl.OPENSSL_VERSION}",
        "curl": first_line([CURL, "--version"]) if CURL else "not found",
        "os": f"{os.name} {sys.platform}",
    }


# --------------------------------------------------------------------------- #
#  One function per verifier. Each returns {"ok": bool | None, "reason": str}
#  ok = None means "could not run" (tool missing, server down).
# --------------------------------------------------------------------------- #
def result(ok: bool | None, reason: str = "") -> dict:
    return {"ok": ok, "reason": reason}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_openssl(sc: dict) -> dict:
    if not OPENSSL:
        return result(None, "openssl not found")
    chain_pem = (REPO / "pki" / sc["chain"]).read_text()
    marker = "-----END CERTIFICATE-----"
    certs = [c + marker + "\n" for c in chain_pem.split(marker) if "BEGIN CERTIFICATE" in c]
    host_opt = ["-verify_ip", sc["host"]] if is_ip(sc["host"]) else ["-verify_hostname", sc["host"]]

    with tempfile.TemporaryDirectory() as tmp:
        leaf = Path(tmp) / "leaf.pem"
        leaf.write_text(certs[0])
        cmd = [OPENSSL, "verify", "-CAfile", str(ROOT_CERT), *host_opt]
        if len(certs) > 1:
            untrusted = Path(tmp) / "untrusted.pem"
            untrusted.write_text("".join(certs[1:]))
            cmd += ["-untrusted", str(untrusted)]
        out = subprocess.run(cmd + [str(leaf)], capture_output=True, text=True, timeout=15)

    text = out.stdout + out.stderr
    if out.returncode == 0 and ": OK" in text:
        return result(True, "OK")
    # "error 64 at depth 0 lookup: IP address mismatch"  ->  "IP address mismatch"
    for line in text.splitlines():
        if line.startswith("error ") and "lookup:" in line:
            return result(False, line.split("lookup:", 1)[1].strip())
    return result(False, text.strip().splitlines()[-1] if text.strip() else f"exit {out.returncode}")


def check_python(sc: dict) -> dict:
    ctx = ssl.create_default_context(cafile=str(ROOT_CERT))
    try:
        with socket.create_connection((sc["host"], sc["port"]), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sc["host"]) as tls:
                return result(True, tls.version() or "OK")
    except ssl.SSLCertVerificationError as e:
        return result(False, (e.verify_message or str(e)).split(",")[0])
    except (ssl.SSLError, OSError) as e:
        return result(None, f"connection failed: {e}")


def check_curl(sc: dict, no_revoke: bool = True) -> dict:
    if not CURL:
        return result(None, "curl not found")
    cmd = [CURL, "-sS", "-o", os.devnull, "--max-time", "10", "--cacert", str(ROOT_CERT)]
    if no_revoke:
        cmd.append("--ssl-no-revoke")
    cmd.append(f"https://{sc['host']}:{sc['port']}/api/ping")
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    if out.returncode == 0:
        return result(True, "OK")
    # "curl: (60) schannel: the certificate ... untrusted root"  ->  text after "schannel: "
    line = out.stderr.strip().splitlines()[0] if out.stderr.strip() else f"exit {out.returncode}"
    line = line.split(") ", 1)[-1].removeprefix("schannel: ")
    return result(False, shorten_schannel(line))


# Windows CryptoAPI chain error bits (CERT_TRUST_STATUS.dwErrorStatus, wincrypt.h).
# curl prints them as "schannel: error 0x00000410".
CERT_TRUST_ERRORS = {
    0x00000001: "IS_NOT_TIME_VALID",
    0x00000004: "IS_REVOKED",
    0x00000008: "IS_NOT_SIGNATURE_VALID",
    0x00000010: "IS_NOT_VALID_FOR_USAGE",
    0x00000020: "IS_UNTRUSTED_ROOT",
    0x00000040: "REVOCATION_STATUS_UNKNOWN",
    0x00000100: "INVALID_EXTENSION",
    0x00000400: "INVALID_BASIC_CONSTRAINTS",
    0x00000800: "INVALID_NAME_CONSTRAINTS",
    0x00004000: "HAS_NOT_PERMITTED_NAME_CONSTRAINT",
    0x00008000: "HAS_EXCLUDED_NAME_CONSTRAINT",
    0x01000000: "IS_PARTIAL_CHAIN",
}
SCHANNEL_TEXT = {
    "the certificate or certificate chain is based on an untrusted root": "untrusted root",
    "this certificate or one of the certificates in the certificate chain is not time valid": "not time valid",
    "SSL peer certificate or SSH remote key was not OK": "peer verification failed",
}


def shorten_schannel(text: str) -> str:
    if text.startswith("error 0x"):
        bits = int(text.split()[1], 16)
        names = [name for bit, name in CERT_TRUST_ERRORS.items() if bits & bit]
        return " + ".join(names) if names else text
    return SCHANNEL_TEXT.get(text, text)


def check_chain_check(chain, anchors, sc: dict, mode: str) -> dict:
    if chain is None:
        return result(None, "server not reachable")
    r = validate(chain, anchors, sc["host"], mode=mode)
    if r["ok"]:
        return result(True, "OK")
    step = next(s for s in r["steps"] if s["status"] == "fail")
    return result(False, f"Step {step['n']} {step['title']}")


# --------------------------------------------------------------------------- #
#  Server: reuse the running one, or start our own
# --------------------------------------------------------------------------- #
def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def ensure_servers() -> tuple[list, str]:
    if all(port_open("127.0.0.1", sc["port"]) for sc in serve.SCENARIOS):
        return [], "using the serve.py that is already running"
    if any(port_open("127.0.0.1", sc["port"]) for sc in serve.SCENARIOS):
        raise SystemExit("error: some Test Bench ports are busy but not all. Stop the other program first.")
    serve.Handler.log_message = lambda *args: None               # keep the table readable
    started = []
    for sc in serve.SCENARIOS:
        started += serve.start(sc)
    return started, "started the 7 servers inside this script"


# --------------------------------------------------------------------------- #
#  Output
# --------------------------------------------------------------------------- #
def browser_expects_ok(sc: dict) -> bool:
    return sc["id"] == "valid"


def cell_status(sc: dict, col: str, res: dict) -> str:
    """'match' | 'known' (documented deviation) | 'unexpected' | 'n/a'"""
    if res["ok"] is None:
        return "n/a"
    if res["ok"] == browser_expects_ok(sc):
        return "match"
    return "known" if (sc["port"], col) in KNOWN_DEVIATIONS else "unexpected"


def cell_text(res: dict) -> str:
    if res["ok"] is None:
        return "– " + res["reason"]
    return ("✅ " if res["ok"] else "❌ ") + res["reason"]


def print_table(rows: list[dict]):
    width = {c: max(len(COLUMN_TITLES[c]), *(len(cell_text(r["results"][c])) for r in rows)) for c in COLUMNS}
    width = {c: min(w, 34) for c, w in width.items()}
    head = f"  {'port':<5} {'scenario':<18} " + " ".join(f"{COLUMN_TITLES[c]:<{width[c]}}" for c in COLUMNS)
    print(paint("1", head))
    print("  " + "─" * (len(head) - 2))
    colour = {"match": "32", "known": "33", "unexpected": "1;31", "n/a": "2"}
    for r in rows:
        cells = []
        for c in COLUMNS:
            text = cell_text(r["results"][c])
            text = text if len(text) <= width[c] else text[: width[c] - 1] + "…"
            cells.append(paint(colour[r["status"][c]], f"{text:<{width[c]}}"))
        print(f"  {r['port']:<5} {r['title']:<18} " + " ".join(cells))
    print(f"\n  {paint('32', 'green')} = same as a browser   {paint('33', 'yellow')} = documented deviation   "
          f"{paint('1;31', 'red')} = unexpected   {paint('2', 'grey')} = could not run")


def markdown(rows: list[dict], versions: dict, when: str, revocation_note: dict) -> str:
    md = [
        "# Test Results Matrix",
        "",
        f"Measured {when} by `tests/run_matrix.py`. ✅ = accepted · ❌ = rejected (reason).",
        "",
        "| Port | Scenario | Expected (browser) | " + " | ".join(f"`{COLUMN_TITLES[c]}`" for c in COLUMNS)
        + " | Edge | Firefox |",
        "|---|---|---|" + "---|" * len(COLUMNS) + "---|---|",
    ]
    for r in rows:
        cells = []
        for c in COLUMNS:
            text = cell_text(r["results"][c])
            cells.append(f"**{text}**" if r["status"][c] == "known" else text)
        md.append(f"| {r['port']} | {r['title']} | {r['expect']} | " + " | ".join(cells) + " | ☐ | ☐ |")
    md += ["", "**Bold** = differs from a browser on purpose (documented deviation):", ""]
    for (port, col), why in KNOWN_DEVIATIONS.items():
        md.append(f"- {port} · `{COLUMN_TITLES[col]}`: {why}")
    md += [
        "",
        "curl on Windows uses Schannel, which checks revocation by default. Our private CA has no CRL/OCSP, so "
        "the curl column uses `--ssl-no-revoke`. Without it, the valid chain gives: "
        f"{cell_text(revocation_note)}.",
        "",
        "Tool versions:",
        "",
    ]
    md += [f"- {k}: {v}" for k, v in versions.items()]
    return "\n".join(md) + "\n"


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if COLOR_ON and os.name == "nt":
        os.system("")                                            # turn on ANSI colours in the Windows console
    if not ROOT_CERT.exists():
        print("error: pki/root/rootCA.crt not found. Run scripts/01..05 first.", file=sys.stderr)
        return 2

    versions = tool_versions()
    print(f"\n  {paint('1', 'G16 · Test Results Matrix')}")
    for k, v in versions.items():
        print(f"  {paint('2', f'{k:<8}')} {v}")

    started, how = ensure_servers()
    print(f"  {paint('2', 'server  ')} {how}\n")

    anchors = load_chain(ROOT_CERT)
    rows = []
    try:
        for sc in serve.SCENARIOS:
            try:
                chain = fetch_chain(sc["host"], sc["port"])
            except OSError:
                chain = None
            res = {
                "openssl": check_openssl(sc),
                "python": check_python(sc),
                "curl": check_curl(sc),
                "fixed": check_chain_check(chain, anchors, sc, "fixed"),
                "vulnerable": check_chain_check(chain, anchors, sc, "vulnerable"),
            }
            rows.append({
                "port": sc["port"], "id": sc["id"], "title": sc["title"], "host": sc["host"],
                "expect": "✅ lock" if browser_expects_ok(sc) else "❌ " + sc["expect"],
                "results": res,
                "status": {c: cell_status(sc, c, res[c]) for c in COLUMNS},
            })
        valid = next(sc for sc in serve.SCENARIOS if sc["id"] == "valid")
        revocation_note = check_curl(valid, no_revoke=False)
    finally:
        for srv in started:
            srv.shutdown()
            srv.server_close()

    print_table(rows)

    known = [(r["port"], c) for r in rows for c in COLUMNS if r["status"][c] == "known"]
    if known:
        print(f"\n  {paint('1', 'Documented deviations')} (findings for the report)")
        for port, col in known:
            print(f"    {port} {COLUMN_TITLES[col]:<23} {KNOWN_DEVIATIONS[(port, col)]}")
    print(f"\n  curl without --ssl-no-revoke on the valid chain: {cell_text(revocation_note)}")

    when = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
    (TESTS / "results.md").write_text(markdown(rows, versions, when, revocation_note), encoding="utf-8")
    (TESTS / "results.json").write_text(json.dumps({
        "measured_at": when, "versions": versions, "rows": rows,
        "curl_with_revocation_check_valid": revocation_note,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  saved    tests/results.md, tests/results.json")

    bad = [(r["port"], c) for r in rows for c in COLUMNS if r["status"][c] in ("unexpected", "n/a")]
    if bad:
        print(paint("1;31", f"\n  {len(bad)} unexpected or missing result(s): "
                            + ", ".join(f"{p}/{c}" for p, c in bad)) + "\n")
        return 1
    print(paint("1;32", "\n  Every result is either the browser behaviour or a documented deviation.") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
