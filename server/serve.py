"""
serve.py - G16 PKI local HTTPS server + PKI Test Bench.

One process, several ports. Every port serves the SAME dashboard, but with a
DIFFERENT certificate chain:

    8443  valid chain (the "green lock" demo)
    8444  wrong name            8447  leaf used as a CA
    8445  expired               8448  Name Constraints violation
    8446  missing SAN           8449  self-signed, not from the G16 CA

Run:   py server/serve.py            (after scripts 01-05)
Stop:  press Enter (Ctrl+C does not reach Python inside Git Bash / mintty)
"""

from __future__ import annotations

import json
import mimetypes
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
from chain_check import describe, load_chain, validate  # noqa: E402

PKI = REPO / "pki"
DASHBOARD = Path(__file__).resolve().parent / "dashboard"
ROOT_CERT = PKI / "root" / "rootCA.crt"

# --------------------------------------------------------------------------- #
#  Test Bench scenarios. Each port = one certificate chain = one lesson.
# --------------------------------------------------------------------------- #
SCENARIOS = [
    {
        "port": 8443, "id": "valid", "host": "localhost",
        "title": "Valid chain",
        "chain": "leaf/fullchain.pem", "key": "leaf/localhost.key",
        "wrong": "Nothing. Root → Intermediate → Leaf, SAN = localhost, 127.0.0.1",
        "expect": "Lock icon (after the root is installed)",
        "theory": "§3.4 Chain of Trust",
    },
    {
        "port": 8444, "id": "wrong-name", "host": "127.0.0.1",
        "title": "Wrong name",
        "chain": "negative/wrong_name.fullchain.pem", "key": "negative/wrong_name.key",
        "wrong": "SAN only has DNS:localhost, but we open it as 127.0.0.1",
        "expect": "NET::ERR_CERT_COMMON_NAME_INVALID",
        "theory": "§3.6 Step 5 · Name",
    },
    {
        "port": 8445, "id": "expired", "host": "localhost",
        "title": "Expired",
        "chain": "negative/expired.fullchain.pem", "key": "negative/expired.key",
        "wrong": "Validity period ended on 2025-04-01",
        "expect": "NET::ERR_CERT_DATE_INVALID",
        "theory": "§3.6 Step 3 · Dates",
    },
    {
        "port": 8446, "id": "no-san", "host": "localhost",
        "title": "Missing SAN",
        "chain": "negative/no_san.fullchain.pem", "key": "negative/no_san.key",
        "wrong": "Only CN=localhost, no Subject Alternative Name",
        "expect": "NET::ERR_CERT_COMMON_NAME_INVALID",
        "theory": "§3.3 SAN vs CN · §5.4",
    },
    {
        "port": 8447, "id": "leaf-as-ca", "host": "localhost",
        "title": "Leaf used as a CA",
        "chain": "negative/leaf_as_ca.fullchain.pem", "key": "negative/leaf_as_ca.key",
        "wrong": "Signed with the key of localhost.crt, which is CA:FALSE",
        "expect": "Rejected (CA rules)",
        "theory": "§5.4 · CVE-2011-0228",
    },
    {
        "port": 8448, "id": "name-constraints", "host": "localhost",
        "title": "Name Constraints",
        "chain": "negative/nc_violation.fullchain.pem", "key": "negative/nc_violation.key",
        "wrong": "Intermediate signed DNS:evil.example, outside its permitted names",
        "expect": "Rejected (CA rules)",
        "theory": "§7.1 · §7.3 Name Constraints",
    },
    {
        "port": 8449, "id": "self-signed", "host": "localhost",
        "title": "Unknown issuer",
        "chain": "negative/self_signed.fullchain.pem", "key": "negative/self_signed.key",
        "wrong": "Self-signed, not issued by G16 Root CA",
        "expect": "NET::ERR_CERT_AUTHORITY_INVALID",
        "theory": "§3.5 Trust store",
    },
]

# The dashboard may "ping" every Test Bench port from the browser to see which
# certificates the browser itself accepts (live browser verdict). Only these
# exact origins are allowed in connect-src.
BENCH_ORIGINS = " ".join(f"https://{s['host']}:{s['port']}" for s in SCENARIOS)

# Security headers for every response.
# NOTE: we do NOT send Strict-Transport-Security. HSTS is stored per HOST, not per
# port, so it would also lock every other localhost port (and break the Test Bench).
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; object-src 'none'; "
                               f"connect-src 'self' {BENCH_ORIGINS}; "
                               "base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def public_scenarios() -> list[dict]:
    keys = ("port", "id", "host", "title", "wrong", "expect", "theory")
    return [{k: s[k] for k in keys} | {"url": f"https://{s['host']}:{s['port']}/"} for s in SCENARIOS]


# --------------------------------------------------------------------------- #
#  HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "G16-PKI"
    sys_version = ""
    scenario: dict = {}          # set per server instance (see make_handler)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._file(DASHBOARD / "index.html")
        if path == "/api/info":
            return self._json(self._info())
        if path == "/api/ping":
            # Reaching this line means the browser completed the TLS handshake,
            # i.e. it ACCEPTED this port's certificate. Public, no secrets: any origin.
            sc = self.scenario
            return self._json({"port": sc["port"], "id": sc["id"]}, cors=True)
        if path.startswith("/static/"):
            target = (DASHBOARD / path[len("/static/"):]).resolve()
            if DASHBOARD.resolve() in target.parents and target.is_file():
                return self._file(target)
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_HEAD(self):
        self._head_only = True
        self.do_GET()

    # ---- API: everything the dashboard shows comes from here -------------
    def _info(self) -> dict:
        sc = self.scenario
        conn: ssl.SSLSocket = self.connection          # type: ignore[assignment]
        cipher_name, _, bits = conn.cipher() or ("?", "?", 0)
        host = (self.headers.get("Host") or sc["host"]).rsplit(":", 1)[0].strip("[]")

        chain = load_chain(PKI / sc["chain"])
        anchors = load_chain(ROOT_CERT)
        result = validate(chain, anchors, host)

        # certificates to draw: the chain the server sends + the root from the trust store
        cards = [describe(c) | {"sent": True} for c in chain]
        root = anchors[0]
        if not any(c["fingerprint"] == describe(root)["fingerprint"] for c in cards) \
                and chain[-1].issuer == root.subject:
            cards.append(describe(root) | {"sent": False})

        return {
            "scenario": {k: v for k, v in sc.items() if k not in ("chain", "key")},
            "connection": {
                "host": host,
                "port": sc["port"],
                "protocol": conn.version(),
                "cipher": cipher_name,
                "bits": bits,
                "client": self.client_address[0],
            },
            "chain": list(reversed(cards)),          # root first, leaf last
            "validation": result,
            "bench": public_scenarios(),
        }

    # ---- helpers ---------------------------------------------------------
    def _file(self, file: Path):
        ctype = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, file.read_bytes(), ctype)

    def _json(self, data: dict, cors: bool = False):
        self._send(200, json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8", cors)

    def _send(self, code: int, body: bytes, ctype: str, cors: bool = False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        proto = getattr(self.connection, "version", lambda: "?")()
        print(f"  [{self.scenario['port']}] {self.address_string():<9} {proto:<7} {fmt % args}")


def make_handler(scenario: dict):
    return type(f"Handler{scenario['port']}", (Handler,), {"scenario": scenario})


# --------------------------------------------------------------------------- #
#  TLS servers
# --------------------------------------------------------------------------- #
def tls_context(chain: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2      # no SSLv3 / TLS 1.0 / 1.1
    ctx.load_cert_chain(certfile=chain, keyfile=key)  # leaf + intermediate, never the root
    return ctx


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows, SO_REUSEADDR lets a SECOND process bind the same port, and the two
    # servers then share the connections at random. Turn it off so a busy port fails loudly.
    allow_reuse_address = False

    def __init__(self, addr, handler, ctx: ssl.SSLContext, family):
        self.address_family = family
        super().__init__(addr, handler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(10)
        # The handshake runs later in the worker thread, so a rejected or slow
        # handshake never blocks the accept loop.
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        # Browsers abort the handshake when they reject a certificate: that is expected.
        err = sys.exc_info()[1]
        if isinstance(err, (ssl.SSLError, ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)

    def verify_request(self, request, client_address):
        return True


def start(scenario: dict) -> list[TLSServer]:
    chain, key = PKI / scenario["chain"], PKI / scenario["key"]
    if not chain.exists() or not key.exists():
        print(f"  [{scenario['port']}] skipped: {chain.relative_to(REPO)} not found")
        return []
    ctx = tls_context(chain, key)
    handler = make_handler(scenario)
    servers = []
    # Listen on loopback only (IPv4 + IPv6), never on the LAN.
    for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            srv = TLSServer((addr, scenario["port"]), handler, ctx, family)
        except OSError as e:
            if family == socket.AF_INET:
                print(f"  [{scenario['port']}] cannot listen: {e}")
            continue
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def main():
    if not ROOT_CERT.exists():
        sys.exit("pki/root/rootCA.crt not found. Run scripts/01..05 first.")
    print("\n  G16 PKI · local HTTPS servers (loopback only)\n")
    running = []
    for sc in SCENARIOS:
        srvs = start(sc)
        if srvs:
            running += srvs
            print(f"  ● {sc['port']}  {sc['title']:<18} https://{sc['host']}:{sc['port']}/")
    if not running:
        sys.exit("No server started. If the ports are busy, another serve.py is probably still running.")
    print("\n  Press Enter to stop.\n")
    try:
        # Git Bash (mintty) does not pass Ctrl+C to Windows programs, so Enter is the stop key.
        input()
    except EOFError:
        # No keyboard (started in the background): run until the process is killed.
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    except KeyboardInterrupt:
        pass
    print("  Stopping...")
    # shutdown() waits up to 0.5 s per server, so stop all of them at the same time
    stoppers = [threading.Thread(target=s.shutdown) for s in running]
    for t in stoppers:
        t.start()
    for t in stoppers:
        t.join()
    for s in running:
        s.server_close()


if __name__ == "__main__":
    mimetypes.add_type("font/woff2", ".woff2")
    mimetypes.add_type("text/javascript", ".js")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
