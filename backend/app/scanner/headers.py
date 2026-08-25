from __future__ import annotations

import httpx

from ..config import CATALOG_DIR
from .allowlist import TargetNotAllowed, validate_local_target

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
]


def catalog_path(target_id: str) -> Path:
    return CATALOG_DIR / f"{target_id.replace('-', '_')}.json"


def identify_target(url: str, explicit_id: str | None = None) -> str:
    if explicit_id in {"juice-shop", "dvwa"}:
        return explicit_id
    lowered = url.lower()
    if ":3000" in lowered or "juice" in lowered:
        return "juice-shop"
    if ":4280" in lowered or "dvwa" in lowered:
        return "dvwa"
    return "generic"


def fingerprint_from_headers(headers: dict[str, str]) -> list[dict]:
    stack: list[dict] = []
    powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
    server = headers.get("server") or headers.get("Server")
    if powered:
        stack.append({"name": powered, "confidence": "high", "version": None})
    if server:
        stack.append({"name": server, "confidence": "medium", "version": None})
    return stack


def inspect_headers(url: str) -> dict:
    """Defensive GET of the target homepage. No payloads, no fuzzing."""
    validate_local_target(url)
    try:
        with httpx.Client(follow_redirects=True, timeout=2.0) as client:
            response = client.get(url)
    except httpx.RequestError as exc:
        return {
            "reachable": False,
            "error": str(exc),
            "missing_headers": [],
            "present_headers": {},
            "tech_hints": [],
            "status_code": None,
        }

    header_map = {k.lower(): v for k, v in response.headers.items()}
    present = {
        name: header_map[name.lower()]
        for name in SECURITY_HEADERS
        if name.lower() in header_map
    }
    missing = [name for name in SECURITY_HEADERS if name.lower() not in header_map]
    return {
        "reachable": True,
        "error": None,
        "missing_headers": missing,
        "present_headers": present,
        "tech_hints": fingerprint_from_headers(dict(response.headers)),
        "status_code": response.status_code,
    }


def header_finding(target_id: str, inspection: dict) -> dict | None:
    if not inspection.get("reachable"):
        return None
    missing = inspection.get("missing_headers") or []
    # HSTS is expected to be absent on local HTTP labs.
    notable = [h for h in missing if h != "Strict-Transport-Security"]
    if not notable:
        return None
    prefix = "JS" if target_id == "juice-shop" else "DVWA" if target_id == "dvwa" else "GEN"
    return {
        "finding_id": f"WEBSET-{prefix}-HDR",
        "title": "Live check: security headers missing on the local target",
        "severity": "medium",
        "confidence": "high",
        "status": "open",
        "detection_type": "dynamic",
        "location": "HTTP response headers",
        "cwe": "CWE-693",
        "owasp": {"id": "A05:2021", "name": "Security Misconfiguration"},
        "nist": "CM-6",
        "sans": "CWE-16",
        "description": (
            "A single unauthenticated GET against the authorised lab URL found missing "
            "browser security headers. This is a configuration review, not an exploit."
        ),
        "evidence": "Missing headers: " + ", ".join(notable),
        "recommendation": (
            "Set CSP, X-Content-Type-Options, a framing policy, Referrer-Policy, "
            "and Permissions-Policy on all responses."
        ),
    }


def generic_findings(inspection: dict) -> list[dict]:
    findings = []
    header = header_finding("generic", inspection)
    if header:
        findings.append(header)
    else:
        findings.append(
            {
                "finding_id": "WEBSET-GEN-001",
                "title": "Local target accepted; no training catalog matched",
                "severity": "info",
                "confidence": "high",
                "status": "open",
                "detection_type": "dynamic",
                "location": "/",
                "cwe": None,
                "owasp": {"id": "A05:2021", "name": "Security Misconfiguration"},
                "nist": "CM-6",
                "sans": "CWE-16",
                "description": (
                    "The URL is on the localhost allow-list, but it is not Juice Shop or DVWA. "
                    "Only header and stack fingerprinting ran. Full OWASP coverage is not claimed."
                ),
                "evidence": (
                    f"Reachable={inspection.get('reachable')}; "
                    f"status={inspection.get('status_code')}"
                ),
                "recommendation": (
                    "Point the demo at Juice Shop (:3000) or DVWA (:4280) for catalog findings, "
                    "or extend the scanner with additional authorised lab profiles."
                ),
            }
        )
    return findings


__all__ = [
    "TargetNotAllowed",
    "catalog_path",
    "header_finding",
    "identify_target",
    "inspect_headers",
    "validate_local_target",
    "generic_findings",
]
