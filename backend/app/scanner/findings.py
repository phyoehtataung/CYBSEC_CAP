from __future__ import annotations

import hashlib
import re

OWASP_TOP_10 = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
]

OWASP_NAMES = {oid: name for oid, name in OWASP_TOP_10}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
DEFAULT_OUT_OF_SCOPE = ["A04:2021 Insecure Design"]


class ScanCancelled(Exception):
    """Raised when the operator cancels a running scan."""


def stable_id(prefix: str, rule_id: str, location: str) -> str:
    digest = hashlib.sha1(f"{rule_id}|{location}".encode("utf-8")).hexdigest()[:8]
    return f"WEBSET-{prefix}-{rule_id}-{digest}"


def redact_evidence(text: str, limit: int = 220) -> str:
    cleaned = re.sub(r"(['\"][^'\"]{8,}['\"])", "'***'", text.strip())
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def make_finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    detection_type: str,
    owasp_id: str,
    description: str,
    recommendation: str,
    confidence: str = "medium",
    status: str = "open",
    location: str | None = None,
    cwe: str | None = None,
    nist: str | None = None,
    sans: str | None = None,
    evidence: str | None = None,
    owasp_name: str | None = None,
) -> dict:
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "detection_type": detection_type,
        "location": location,
        "cwe": cwe,
        "owasp": {"id": owasp_id, "name": owasp_name or OWASP_NAMES.get(owasp_id, owasp_id)},
        "nist": nist,
        "sans": sans,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def summarise(findings: list[dict]) -> dict:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        level = finding.get("severity", "info")
        if level in counts:
            counts[level] += 1
    counts["total"] = len(findings)
    return counts


def coverage_from_findings(findings: list[dict], out_of_scope: list[str], notes: str) -> dict:
    detected_ids = {f.get("owasp", {}).get("id") for f in findings}
    owasp = []
    for oid, name in OWASP_TOP_10:
        if any(oid in item for item in out_of_scope):
            status = "out_of_scope"
        elif oid in detected_ids:
            status = "detected"
        else:
            status = "not_detected"
        owasp.append({"id": oid, "name": name, "status": status})
    return {"owasp": owasp, "out_of_scope": out_of_scope, "notes": notes}


def merge_tech_stack(*groups: list[dict]) -> list[dict]:
    merged: list[dict] = []
    known: set[str] = set()
    for group in groups:
        for item in group or []:
            name = (item.get("name") or "").strip()
            if not name or name in known:
                continue
            known.add(name)
            merged.append(
                {
                    "name": name,
                    "version": item.get("version"),
                    "confidence": item.get("confidence", "medium"),
                }
            )
    return merged


def dedupe_findings(live: list[dict], catalog: list[dict]) -> tuple[list[dict], list[dict]]:
    """Keep all live findings. Add catalog items whose CWE (or OWASP id) is not already covered."""
    covered_cwe = {item.get("cwe") for item in live if item.get("cwe")}
    covered_owasp = {item.get("owasp", {}).get("id") for item in live}
    extra = []
    for item in catalog:
        cwe = item.get("cwe")
        oid = item.get("owasp", {}).get("id")
        if cwe and cwe in covered_cwe:
            continue
        if not cwe and oid and oid in covered_owasp:
            continue
        extra.append(item)
        if cwe:
            covered_cwe.add(cwe)
        if oid:
            covered_owasp.add(oid)
    return live + extra, extra
