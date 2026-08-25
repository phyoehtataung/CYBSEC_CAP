from datetime import datetime
import json

from sqlalchemy.orm import Session

from .models import Case, Finding, Scan


def finding_to_dict(row: Finding) -> dict:
    return {
        "finding_id": row.finding_id,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "status": row.status,
        "detection_type": row.detection_type,
        "location": row.location,
        "cwe": row.cwe,
        "owasp": {"id": row.owasp_id, "name": row.owasp_name},
        "nist": row.nist,
        "sans": row.sans,
        "description": row.description,
        "evidence": row.evidence,
        "recommendation": row.recommendation,
    }


def scan_to_summary(scan: Scan) -> dict:
    result = {}
    if scan.result_json:
        try:
            result = json.loads(scan.result_json)
        except json.JSONDecodeError:
            result = {}
    summary = result.get("summary") or {
        "total": len(scan.findings),
        "critical": sum(1 for f in scan.findings if f.severity == "critical"),
        "high": sum(1 for f in scan.findings if f.severity == "high"),
        "medium": sum(1 for f in scan.findings if f.severity == "medium"),
        "low": sum(1 for f in scan.findings if f.severity == "low"),
        "info": sum(1 for f in scan.findings if f.severity == "info"),
    }
    return {
        "scan_id": scan.id,
        "case_id": scan.case_id,
        "target_name": scan.target_name,
        "target_url": scan.target_url,
        "status": scan.status,
        "progress": scan.progress,
        "message": scan.message,
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "summary": summary,
        "tech_stack": result.get("tech_stack", []),
    }


def scan_to_detail(scan: Scan) -> dict:
    if scan.result_json:
        try:
            payload = json.loads(scan.result_json)
            if payload.get("findings") is not None:
                payload["progress"] = scan.progress
                payload["message"] = scan.message
                return payload
        except json.JSONDecodeError:
            pass
    return {
        **scan_to_summary(scan),
        "findings": [finding_to_dict(f) for f in scan.findings],
    }


def case_to_dict(case: Case) -> dict:
    scans = sorted(case.scans, key=lambda s: s.started_at or datetime.min, reverse=True)
    latest = scans[0] if scans else None
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for scan in scans:
        summary = scan_to_summary(scan)["summary"]
        for key in totals:
            totals[key] += summary.get(key, 0)
    return {
        "case_id": case.id,
        "title": case.title,
        "application": case.application,
        "owner": {
            "id": case.owner.id,
            "name": case.owner.name,
            "email": case.owner.email,
            "role": case.owner.role,
        },
        "created_at": _iso(case.created_at),
        "notes": case.notes,
        "scan_count": len(scans),
        "latest_scan": scan_to_summary(latest) if latest else None,
        "totals": totals,
        "scans": [scan_to_summary(s) for s in scans],
    }


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def dashboard_payload(db: Session) -> dict:
    scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
    cases = db.query(Case).all()
    findings = db.query(Finding).all()
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp: dict[str, int] = {}
    stacks: dict[str, int] = {}
    for finding in findings:
        if finding.severity in severity:
            severity[finding.severity] += 1
        owasp[finding.owasp_id] = owasp.get(finding.owasp_id, 0) + 1
    for scan in scans:
        try:
            result = json.loads(scan.result_json or "{}")
        except json.JSONDecodeError:
            result = {}
        for item in result.get("tech_stack", []):
            name = item.get("name")
            if name:
                stacks[name] = stacks.get(name, 0) + 1
    completed = [s for s in scans if s.status == "completed"]
    return {
        "totals": {
            "cases": len(cases),
            "scans": len(scans),
            "findings": len(findings),
            "open_critical": severity["critical"],
        },
        "severity": severity,
        "owasp": [{"id": k, "count": v} for k, v in sorted(owasp.items())],
        "tech_stacks": [{"name": k, "scans": v} for k, v in sorted(stacks.items(), key=lambda x: -x[1])],
        "recent_scans": [scan_to_summary(s) for s in scans[:8]],
        "trend": [
            {
                "scan_id": s.id,
                "started_at": _iso(s.started_at),
                "target_name": s.target_name,
                "total": scan_to_summary(s)["summary"].get("total", 0),
                "critical": scan_to_summary(s)["summary"].get("critical", 0),
            }
            for s in reversed(completed[-6:])
        ],
    }
