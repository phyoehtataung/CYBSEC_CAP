from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from ..config import APP_NAME, APP_VERSION, SCHEMA_VERSION
from .headers import (
    catalog_path,
    generic_findings,
    header_finding,
    identify_target,
    inspect_headers,
)

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

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_catalog(target_id: str) -> dict | None:
    path = catalog_path(target_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


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


def build_scan_result(
    *,
    scan_id: str,
    case_id: str,
    target_name: str,
    target_url: str,
    started_at: datetime,
    catalog: dict | None,
    inspection: dict,
    target_id: str,
) -> dict:
    findings: list[dict] = []
    tech_stack: list[dict] = []
    out_of_scope = ["A04:2021 Insecure Design"]
    notes = (
        "This prototype combines a live header check with a training-app catalog. "
        "It does not send exploit payloads. A04 Insecure Design is out of scope."
    )

    if catalog:
        findings = list(catalog.get("findings", []))
        tech_stack = list(catalog.get("tech_stack", []))
        out_of_scope = catalog.get("out_of_scope", out_of_scope)
        notes = catalog.get("coverage_notes", notes)
        live = header_finding(target_id, inspection)
        if live:
            # Replace catalog header finding evidence with live evidence when present.
            replaced = False
            for item in findings:
                if item.get("detection_type") == "dynamic" and "header" in item.get("title", "").lower():
                    item["evidence"] = live["evidence"]
                    item["confidence"] = "high"
                    replaced = True
                    break
            if not replaced:
                findings.append(live)
    else:
        findings = generic_findings(inspection)
        tech_stack = inspection.get("tech_hints") or []

    if inspection.get("tech_hints"):
        known = {item["name"] for item in tech_stack}
        for hint in inspection["tech_hints"]:
            if hint["name"] not in known:
                tech_stack.append(hint)

    completed = utcnow()
    status = "completed"
    if not inspection.get("reachable"):
        notes += (
            f" Live target was not reachable ({inspection.get('error')}). "
            "Catalog findings were still recorded for the selected lab profile."
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "case_id": case_id,
        "target": {
            "name": target_name,
            "url": target_url,
            "authorized": True,
            "environment": "local",
        },
        "scanner": {
            "name": APP_NAME,
            "version": APP_VERSION,
            "modes": ["static", "dynamic", "catalog"],
        },
        "started_at": started_at.isoformat(),
        "completed_at": completed.isoformat(),
        "status": status,
        "tech_stack": tech_stack,
        "summary": summarise(findings),
        "coverage": coverage_from_findings(findings, out_of_scope, notes),
        "live_check": {
            "reachable": bool(inspection.get("reachable")),
            "status_code": inspection.get("status_code"),
            "error": inspection.get("error"),
            "missing_headers": inspection.get("missing_headers") or [],
        },
        "findings": findings,
    }


def run_scan(
    *,
    scan_id: str | None = None,
    case_id: str,
    target_name: str,
    target_url: str,
    target_id: str | None = None,
) -> dict:
    started = utcnow()
    scan_id = scan_id or str(uuid4())
    resolved_id = identify_target(target_url, target_id)
    catalog = load_catalog(resolved_id)
    inspection = inspect_headers(target_url)
    name = target_name or (catalog["target_name"] if catalog else "Local lab target")
    return build_scan_result(
        scan_id=scan_id,
        case_id=case_id,
        target_name=name,
        target_url=target_url,
        started_at=started,
        catalog=catalog,
        inspection=inspection,
        target_id=resolved_id,
    )
