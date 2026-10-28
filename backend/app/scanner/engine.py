from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from ..config import APP_NAME, APP_VERSION, SCHEMA_VERSION
from .allowlist import validate_local_target
from .dynamic.engine import run_dynamic
from .findings import (
    DEFAULT_OUT_OF_SCOPE,
    ScanCancelled,
    coverage_from_findings,
    dedupe_findings,
    merge_tech_stack,
    summarise,
)
from .headers import catalog_path, identify_target
from .static.engine import run_static


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_catalog(target_id: str) -> dict | None:
    path = catalog_path(target_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _emit(progress, pct: int, message: str, cancelled=None) -> None:
    if cancelled and cancelled():
        raise ScanCancelled()
    if progress:
        progress(max(0, min(100, pct)), message)


def build_scan_result(
    *,
    scan_id: str,
    case_id: str,
    target_name: str,
    target_url: str,
    started_at: datetime,
    findings: list[dict],
    tech_stack: list[dict],
    modes: list[str],
    out_of_scope: list[str],
    notes: str,
    live_check: dict,
    status: str = "completed",
    completed_at: datetime | None = None,
) -> dict:
    completed = completed_at or utcnow()
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
            "modes": modes,
        },
        "started_at": started_at.isoformat(),
        "completed_at": completed.isoformat(),
        "status": status,
        "tech_stack": tech_stack,
        "summary": summarise(findings),
        "coverage": coverage_from_findings(findings, out_of_scope, notes),
        "live_check": {
            "reachable": bool(live_check.get("reachable")),
            "status_code": live_check.get("status_code"),
            "error": live_check.get("error"),
            "missing_headers": live_check.get("missing_headers") or [],
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
    progress=None,
    cancelled=None,
) -> dict:
    started = utcnow()
    scan_id = scan_id or str(uuid4())
    findings: list[dict] = []
    modes: list[str] = []
    notes: list[str] = []
    tech_stack: list[dict] = []
    live_check = {
        "reachable": False,
        "status_code": None,
        "error": None,
        "missing_headers": [],
    }
    status = "completed"
    catalog = None
    resolved_id = "generic"
    name = target_name or "Local lab target"

    try:
        _emit(progress, 5, "Checking local allow-list", cancelled)
        url = validate_local_target(target_url)

        _emit(progress, 10, "Identifying the local target", cancelled)
        resolved_id = identify_target(url, target_id)
        catalog = load_catalog(resolved_id)
        name = target_name or (catalog["target_name"] if catalog else "Local lab target")
        out_of_scope = list((catalog or {}).get("out_of_scope") or DEFAULT_OUT_OF_SCOPE)

        _emit(progress, 15, "Running static analysis", cancelled)

        def static_progress(pct, message):
            _emit(progress, 15 + int(pct * 0.25), message, cancelled)

        static = run_static(resolved_id, progress=static_progress, cancelled=cancelled)
        if static["ran"]:
            modes.append("static")
            findings.extend(static["findings"])
            tech_stack = merge_tech_stack(tech_stack, static.get("tech_stack") or [])
        notes.append(static["notes"])

        _emit(progress, 42, "Running dynamic analysis", cancelled)

        def dynamic_progress(pct, message):
            _emit(progress, 42 + int(pct * 0.45), message, cancelled)

        dynamic = run_dynamic(url, resolved_id, progress=dynamic_progress, cancelled=cancelled)
        live_check = dynamic.get("inspection") or live_check
        if dynamic["ran"]:
            modes.append("dynamic")
            findings.extend(dynamic["findings"])
            tech_stack = merge_tech_stack(tech_stack, dynamic.get("tech_stack") or [])
        notes.append(dynamic["notes"])

        _emit(progress, 90, "Normalising findings to the WebSET schema", cancelled)
        catalog_findings = list((catalog or {}).get("findings") or [])
        if catalog_findings:
            findings, extra = dedupe_findings(findings, catalog_findings)
            if extra:
                modes.append("catalog")
                notes.append(
                    "Training-app catalog entries were added for OWASP classes not confirmed by live checks."
                )
            elif not findings:
                findings = catalog_findings
                modes.append("catalog")
                notes.append("Catalog findings were recorded because live checks produced none.")
        tech_stack = merge_tech_stack(tech_stack, (catalog or {}).get("tech_stack") or [])
        notes.append(
            "WebSET does not send exploit payloads. A04 Insecure Design is out of scope."
        )
        if catalog and catalog.get("coverage_notes") and "catalog" in modes:
            notes.append(catalog["coverage_notes"])

    except ScanCancelled:
        status = "cancelled"
        notes.append("Scan cancelled by the user before completion.")

    note_text = " ".join(part.strip() for part in notes if part)
    if not modes:
        modes = ["dynamic"] if live_check.get("reachable") else []

    return build_scan_result(
        scan_id=scan_id,
        case_id=case_id,
        target_name=name,
        target_url=target_url,
        started_at=started,
        findings=findings,
        tech_stack=tech_stack,
        modes=modes,
        out_of_scope=list((catalog or {}).get("out_of_scope") or DEFAULT_OUT_OF_SCOPE),
        notes=note_text,
        live_check=live_check,
        status=status,
    )
