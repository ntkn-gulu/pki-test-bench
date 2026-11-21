"""
verify_chain.py - Validate a certificate chain step by step, from the command line.

It runs the 6 checks of the midterm report (Section 3.6) with tools/chain_check.py
and prints every step. With --mode vulnerable the Basic Constraints check is
switched off, which reproduces CVE-2011-0228: a leaf certificate (CA:FALSE) can
then sign a certificate for any name and the chain is still accepted.

Where the chain comes from:
  --port 8447            connect to the running Test Bench server and read the
                         chain it really sends during the TLS handshake
  --port 8447 --offline  read the same scenario from pki/ (server not needed)
  --file some.pem        any PEM file, leaf first (like fullchain.pem)

Examples (Git Bash, from the repo root):
  py tools/verify_chain.py --list
  py tools/verify_chain.py --port 8443
  py tools/verify_chain.py --port 8447 --mode vulnerable
  py tools/verify_chain.py --port 8447 --mode both
  py tools/verify_chain.py --file pki/leaf/fullchain.pem --host localhost

Exit code: 0 = chain accepted, 1 = chain rejected, 2 = input error.
With --mode both, the exit code follows the "fixed" result.
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
from pathlib import Path

from cryptography import x509

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "server"))
from chain_check import FAIL, PASS, describe, load_chain, validate  # noqa: E402
from serve import ROOT_CERT, SCENARIOS                              # noqa: E402  (one source of truth)

EXIT_ACCEPTED, EXIT_REJECTED, EXIT_INPUT_ERROR = 0, 1, 2


# --------------------------------------------------------------------------- #
#  Terminal colours (off when piped, or when NO_COLOR is set)
# --------------------------------------------------------------------------- #
class Style:
    on = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.on else text


def green(t: str) -> str: return Style.wrap("1;32", t)
def red(t: str) -> str:   return Style.wrap("1;31", t)
def blue(t: str) -> str:  return Style.wrap("1;34", t)
def dim(t: str) -> str:   return Style.wrap("2", t)
def bold(t: str) -> str:  return Style.wrap("1", t)


MARK = {PASS: lambda: green("✓"), FAIL: lambda: red("✕"), "skip": lambda: dim("–")}


def verdict(ok: bool) -> str:
    return green("✓ ACCEPTED") if ok else red("✕ REJECTED")


# --------------------------------------------------------------------------- #
#  Getting the chain
# --------------------------------------------------------------------------- #
def scenario_for(port: int) -> dict:
    for sc in SCENARIOS:
        if sc["port"] == port:
            return sc
    ports = ", ".join(str(s["port"]) for s in SCENARIOS)
    raise LookupError(f"no Test Bench scenario on port {port} (known: {ports})")


def fetch_chain(host: str, port: int) -> list[x509.Certificate]:
    """
    Do a TLS handshake WITHOUT verification and return the certificates the server sent.
    Verification is off on purpose: we want to look at broken chains too, and the
    decision is made by validate(), not by the ssl module.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der_list = tls.get_unverified_chain()           # Python 3.13+, leaf first
    return [x509.load_der_x509_certificate(bytes(der)) for der in der_list]


def short_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------- #
#  Printing
# --------------------------------------------------------------------------- #
def print_header(source: str, host: str, anchors: list[x509.Certificate], root_file: Path, mode: str):
    print()
    print(f"  {bold('G16 · verify_chain')}   {dim('midterm §3.6, six steps')}   mode: {blue(mode)}")
    print(f"  {dim('source')}   {source}")
    print(f"  {dim('host  ')}   {host}   {dim('(the name in the address bar)')}")
    anchor_names = ", ".join(describe(a)["subject"] for a in anchors)
    print(f"  {dim('trust ')}   {anchor_names}   {dim('(' + short_path(root_file) + ')')}")


def print_chain(chain: list[x509.Certificate]):
    print(f"\n  {bold('Chain sent by the server')} {dim('(leaf first, root is never sent)')}")
    infos = [describe(c) for c in chain]
    width = max(len(i["subject"]) for i in infos)
    for idx, info in enumerate(infos):
        ca = blue("CA:TRUE") if info["is_ca"] else "CA:FALSE"
        if info["is_ca"] and info["path_len"] is not None:
            ca += f", pathlen:{info['path_len']}"
        extra = ""
        if info["san"]:
            extra = "SAN " + ", ".join(info["san"])
        elif not info["is_ca"]:
            extra = red("no SAN")
        if info["name_constraints"]:
            extra = "permits " + ", ".join(info["name_constraints"])
        print(f"    [{idx}] {info['subject']:<{width}}  {dim('issued by')} {info['issuer']}")
        print(f"        {' ' * width}  {ca}   {extra}   {dim('expires ' + info['not_after'][:10])}")


def print_single(result: dict):
    print(f"\n  {bold('Validation')}")
    for s in result["steps"]:
        detail = red(s["detail"]) if s["status"] == FAIL else s["detail"]
        print(f"    {s['n']}  {s['title']:<16} {MARK[s['status']]()}  {detail}")
    tail = f"   {red(result['error'])}" if result["error"] else ""
    print(f"\n  RESULT   {verdict(result['ok'])}{tail}\n")


def print_both(fixed: dict, vuln: dict):
    print(f"\n  {bold('Validation')}            {dim('fixed')}  {dim('vulnerable')}")
    for f, v in zip(fixed["steps"], vuln["steps"]):
        print(f"    {f['n']}  {f['title']:<16}   {MARK[f['status']]()}      {MARK[v['status']]()}")

    print(f"\n  RESULT   fixed       {verdict(fixed['ok'])}"
          + (f"   {red(fixed['error'])}" if fixed["error"] else ""))
    print(f"           vulnerable  {verdict(vuln['ok'])}"
          + (f"   {red(vuln['error'])}" if vuln["error"] else ""))

    # Explain only the steps where the two verifiers disagree
    diffs = [(f, v) for f, v in zip(fixed["steps"], vuln["steps"]) if f["status"] != v["status"]]
    if diffs:
        print(f"\n  {bold('Why they differ')}")
        for f, v in diffs:
            print(f"    step {f['n']} {f['title']}")
            print(f"      fixed       {MARK[f['status']]()}  {f['detail']}")
            print(f"      vulnerable  {MARK[v['status']]()}  {v['detail']}")
    if vuln["ok"] and not fixed["ok"]:
        print(f"\n  {red('!')} The vulnerable verifier accepts a chain that a correct verifier rejects.")
        print("    One missing Basic Constraints check is enough to break the whole trust model (CVE-2011-0228).")
    print()


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="verify_chain.py",
        description="Validate a certificate chain with the 6 steps of midterm Section 3.6.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  py tools/verify_chain.py --port 8443\n"
               "  py tools/verify_chain.py --port 8447 --mode both\n"
               "  py tools/verify_chain.py --file pki/leaf/fullchain.pem --host localhost",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--port", type=int, help="Test Bench port (8443-8449): read the chain from the running server")
    src.add_argument("--file", type=Path, help="PEM file with the chain, leaf first")
    src.add_argument("--list", action="store_true", help="list the Test Bench scenarios and exit")
    p.add_argument("--offline", action="store_true", help="with --port: read the scenario's chain from pki/ instead")
    p.add_argument("--host", help="hostname to check against the SAN (default: the scenario's host, or localhost)")
    p.add_argument("--root", type=Path, default=ROOT_CERT, help="trusted root certificate(s), PEM (default: %(default)s)")
    p.add_argument("--mode", choices=("fixed", "vulnerable", "both"), default="fixed",
                   help="fixed = all checks; vulnerable = skip Basic Constraints (CVE-2011-0228); both = compare")
    args = p.parse_args(argv)
    if not (args.port or args.file or args.list):
        p.error("give --port, --file or --list")
    if args.offline and not args.port:
        p.error("--offline only works with --port")
    return args


def print_scenarios():
    print(f"\n  {bold('Test Bench scenarios')}")
    for sc in SCENARIOS:
        print(f"    {sc['port']}  {sc['title']:<18} https://{sc['host']}:{sc['port']}/   {dim(sc['expect'])}")
    print()


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if Style.on and os.name == "nt":
        os.system("")                                       # turn on ANSI colours in the Windows console

    args = parse_args(argv)
    if args.list:
        print_scenarios()
        return EXIT_ACCEPTED

    try:
        anchors = load_chain(args.root)
        if args.port:
            sc = scenario_for(args.port)
            host = args.host or sc["host"]
            if args.offline:
                chain_file = REPO / "pki" / sc["chain"]
                chain = load_chain(chain_file)
                source = f"{short_path(chain_file)}   {dim('(port ' + str(sc['port']) + ' · ' + sc['title'] + ', offline)')}"
            else:
                chain = fetch_chain(sc["host"], sc["port"])
                source = (f"https://{sc['host']}:{sc['port']}/   "
                          f"{dim('(live TLS handshake · ' + sc['title'] + ' · ' + str(len(chain)) + ' certs sent)')}")
        else:
            host = args.host or "localhost"
            chain = load_chain(args.file)
            source = short_path(args.file)
    except FileNotFoundError as e:
        print(f"error: file not found: {e.filename}. Run scripts/01..05 first.", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except (ConnectionError, TimeoutError, OSError) as e:
        print(f"error: cannot connect ({e}). Is the server running?  py server/serve.py\n"
              f"       Or read the chain from disk with --offline.", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except LookupError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except ValueError as e:
        print(f"error: cannot read the certificates: {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    if not chain:
        print("error: no certificate found", file=sys.stderr)
        return EXIT_INPUT_ERROR

    print_header(source, host, anchors, args.root, args.mode)
    print_chain(chain)

    if args.mode == "both":
        fixed = validate(chain, anchors, host, mode="fixed")
        vuln = validate(chain, anchors, host, mode="vulnerable")
        print_both(fixed, vuln)
        return EXIT_ACCEPTED if fixed["ok"] else EXIT_REJECTED

    result = validate(chain, anchors, host, mode=args.mode)
    print_single(result)
    return EXIT_ACCEPTED if result["ok"] else EXIT_REJECTED


if __name__ == "__main__":
    sys.exit(main())
