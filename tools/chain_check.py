"""
chain_check.py - Certificate chain validation, step by step.

This module re-implements the 6 checks a browser performs (midterm report, Section 3.6)
so that we can SHOW each step, and so that we can switch one check off on purpose
("vulnerable" mode) to reproduce CVE-2011-0228 (missing Basic Constraints check).

It is a teaching tool. Real software must use the platform verifier or OpenSSL.

Used by:
  - server/serve.py      -> the dashboard shows the result of each step
  - tools/verify_chain.py (command line, vulnerable vs fixed)
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

PASS, FAIL, SKIP = "pass", "fail", "skip"


# --------------------------------------------------------------------------- #
#  Loading and describing certificates
# --------------------------------------------------------------------------- #
def load_chain(path: str | Path) -> list[x509.Certificate]:
    """Load every PEM certificate from a file (leaf first, like fullchain.pem)."""
    return x509.load_pem_x509_certificates(Path(path).read_bytes())


def _ext(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def _san_list(cert: x509.Certificate) -> list[str]:
    ext = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if ext is None:
        return []
    out = [f"DNS:{d}" for d in ext.value.get_values_for_type(x509.DNSName)]
    out += [f"IP:{ip}" for ip in ext.value.get_values_for_type(x509.IPAddress)]
    return out


def _key_desc(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name}"
    return type(key).__name__


def _is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:
        return False


def describe(cert: x509.Certificate) -> dict:
    """Turn a certificate into plain JSON-friendly data for the dashboard."""
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    ku = _ext(cert, ExtensionOID.KEY_USAGE)
    eku = _ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    nc = _ext(cert, ExtensionOID.NAME_CONSTRAINTS)

    key_usage = []
    if ku is not None:
        v = ku.value
        for name in ("digital_signature", "key_encipherment", "key_cert_sign", "crl_sign"):
            if getattr(v, name):
                key_usage.append(name)

    permitted = []
    if nc is not None and nc.value.permitted_subtrees:
        for gn in nc.value.permitted_subtrees:
            if isinstance(gn, x509.DNSName):
                permitted.append(f"DNS:{gn.value}")
            elif isinstance(gn, x509.IPAddress):
                permitted.append(f"IP:{gn.value}")

    now = dt.datetime.now(dt.timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    total = (na - nb).total_seconds()
    used = (now - nb).total_seconds()

    return {
        "subject": _cn(cert.subject),
        "subject_full": cert.subject.rfc4514_string(),
        "issuer": _cn(cert.issuer),
        "self_signed": _is_self_signed(cert),
        "serial": format(cert.serial_number, "X"),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "lifetime_days": round(total / 86400),
        "days_left": round((na - now).total_seconds() / 86400),
        "lifetime_used": max(0.0, min(1.0, used / total)) if total > 0 else 1.0,
        "key": _key_desc(cert),
        "signature": cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "?",
        "is_ca": bool(bc and bc.value.ca),
        "path_len": bc.value.path_length if bc else None,
        "key_usage": key_usage,
        "ext_key_usage": [o._name for o in eku.value] if eku else [],
        "san": _san_list(cert),
        "name_constraints": permitted,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


# --------------------------------------------------------------------------- #
#  Small helpers for the checks
# --------------------------------------------------------------------------- #
def _host_matches(san: list[str], host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return f"IP:{ip}" in san
    except ValueError:
        host = host.lower().rstrip(".")
        for entry in san:
            if not entry.startswith("DNS:"):
                continue
            name = entry[4:].lower()
            if name == host:
                return True
            # wildcard: *.example.com matches a.example.com (one label only)
            if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
                return True
        return False


def _within_constraints(entry: str, permitted: list[str]) -> bool:
    kind, value = entry.split(":", 1)
    for p in permitted:
        pkind, pval = p.split(":", 1)
        if kind != pkind:
            continue
        if kind == "DNS" and (value == pval or value.endswith("." + pval)):
            return True
        if kind == "IP" and ipaddress.ip_address(value) in ipaddress.ip_network(pval, strict=False):
            return True
    # no constraint of this type -> allowed
    return not any(p.startswith(kind + ":") for p in permitted)


# --------------------------------------------------------------------------- #
#  The 6 steps (midterm Section 3.6)
# --------------------------------------------------------------------------- #
def validate(
    chain: list[x509.Certificate],
    anchors: list[x509.Certificate],
    hostname: str,
    mode: str = "fixed",
    now: dt.datetime | None = None,
) -> dict:
    """
    chain    : certificates sent by the server, leaf first
    anchors  : trusted roots (our "trust store")
    hostname : name typed in the address bar
    mode     : "fixed"      -> all checks (correct behaviour)
               "vulnerable" -> skip the issuer CA checks, like CVE-2011-0228
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    steps: list[dict] = []
    leaf = chain[0]

    # ---- Step 1: build the path up to a trusted root -----------------------
    anchor = None
    top = chain[-1]
    for root in anchors:
        if top.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
            anchor, path = root, list(chain)
            break
        if top.issuer == root.subject:
            anchor, path = root, list(chain) + [root]
            break
    if anchor is None:
        path = list(chain)
        steps.append(_step(1, "Path", FAIL,
                           f"'{_cn(top.issuer)}' is not in the trust store",
                           "NET::ERR_CERT_AUTHORITY_INVALID"))
    else:
        names = " → ".join(_cn(c.subject) for c in reversed(path))
        steps.append(_step(1, "Path", PASS, f"{names}  (anchor found in trust store)"))

    # ---- Step 2: every signature is valid ----------------------------------
    bad_sig = None
    for child, parent in zip(path, path[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except Exception:
            bad_sig = child
            break
    if anchor is None:
        steps.append(_step(2, "Signatures", SKIP, "no complete path to check"))
    elif bad_sig is not None:
        steps.append(_step(2, "Signatures", FAIL, f"signature of '{_cn(bad_sig.subject)}' is invalid",
                           "NET::ERR_CERT_INVALID"))
    else:
        steps.append(_step(2, "Signatures", PASS, f"{len(path) - 1} signatures verified"))

    # ---- Step 3: dates -----------------------------------------------------
    expired = [c for c in path if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc)]
    if expired:
        c = expired[0]
        steps.append(_step(3, "Dates", FAIL,
                           f"'{_cn(c.subject)}' valid {c.not_valid_before_utc:%Y-%m-%d} → "
                           f"{c.not_valid_after_utc:%Y-%m-%d}, now is {now:%Y-%m-%d}",
                           "NET::ERR_CERT_DATE_INVALID"))
    else:
        steps.append(_step(3, "Dates", PASS, "every certificate is inside its validity period"))

    # ---- Step 4: CA rules (Basic Constraints, pathlen, Key Usage, Name Constraints)
    problems = []
    if mode == "vulnerable":
        # CVE-2011-0228: the issuer is never checked to be a CA.
        ca_detail = "SKIPPED in vulnerable mode (CVE-2011-0228)"
    else:
        for depth, issuer in enumerate(path[1:], start=1):
            bc = _ext(issuer, ExtensionOID.BASIC_CONSTRAINTS)
            if not (bc and bc.value.ca):
                problems.append(f"'{_cn(issuer.subject)}' is CA:FALSE but signed a certificate")
                continue
            ku = _ext(issuer, ExtensionOID.KEY_USAGE)
            if ku and not ku.value.key_cert_sign:
                problems.append(f"'{_cn(issuer.subject)}' Key Usage has no keyCertSign")
            # CA certificates between this issuer and the leaf (self-issued ones do not count)
            below = [c for c in path[1:depth] if c.issuer != c.subject]
            if bc.value.path_length is not None and len(below) > bc.value.path_length:
                problems.append(f"'{_cn(issuer.subject)}' pathlen:{bc.value.path_length} exceeded")
        ca_detail = "every issuer is CA:TRUE with keyCertSign, pathlen respected"

    # Name Constraints are checked in both modes (they are a separate feature)
    leaf_names = _san_list(leaf) or [f"DNS:{_cn(leaf.subject)}"]
    for issuer in path[1:]:
        nc = _ext(issuer, ExtensionOID.NAME_CONSTRAINTS)
        if nc is None or not nc.value.permitted_subtrees:
            continue
        permitted = describe(issuer)["name_constraints"]
        outside = [n for n in leaf_names if not _within_constraints(n, permitted)]
        if outside:
            problems.append(f"{', '.join(outside)} is outside the Name Constraints of "
                            f"'{_cn(issuer.subject)}' ({', '.join(permitted)})")

    eku = _ext(leaf, ExtensionOID.EXTENDED_KEY_USAGE)
    if eku and ExtendedKeyUsageOID.SERVER_AUTH not in eku.value:
        problems.append("leaf is not allowed for TLS server authentication (EKU)")

    if problems:
        steps.append(_step(4, "CA rules", FAIL, "; ".join(problems), "NET::ERR_CERT_INVALID"))
    else:
        steps.append(_step(4, "CA rules", PASS, ca_detail + ", Name Constraints OK"))

    # ---- Step 5: the name in the address bar must be in the SAN ------------
    san = _san_list(leaf)
    if not san:
        steps.append(_step(5, "Name", FAIL,
                           f"no Subject Alternative Name (CN='{_cn(leaf.subject)}' is ignored by browsers)",
                           "NET::ERR_CERT_COMMON_NAME_INVALID"))
    elif _host_matches(san, hostname):
        steps.append(_step(5, "Name", PASS, f"'{hostname}' found in SAN ({', '.join(san)})"))
    else:
        steps.append(_step(5, "Name", FAIL, f"'{hostname}' is not in SAN ({', '.join(san)})",
                           "NET::ERR_CERT_COMMON_NAME_INVALID"))

    # ---- Step 6: revocation and Certificate Transparency -------------------
    steps.append(_step(6, "Revocation & CT", SKIP,
                       "private CA: no CRL/OCSP endpoint, no CT logs "
                       "(browsers do not require CT for locally installed roots)"))

    failed = [s for s in steps if s["status"] == FAIL]
    return {
        "ok": not failed,
        "mode": mode,
        "hostname": hostname,
        "error": failed[0]["error"] if failed else None,
        "steps": steps,
    }


def _step(n: int, title: str, status: str, detail: str, error: str | None = None) -> dict:
    return {"n": n, "title": title, "status": status, "detail": detail, "error": error}
