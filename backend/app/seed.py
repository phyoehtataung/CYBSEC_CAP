from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

from sqlalchemy.orm import Session

from .models import Case, Finding, Scan, User
from .scanner.engine import load_catalog, build_scan_result

DEMO_USER_ID = "usr-analyst-01"


def persist_result(db: Session, scan: Scan, result: dict) -> None:
    scan.status = result["status"]
    scan.progress = 100
    if result["status"] == "cancelled":
        scan.message = "Scan cancelled"
    elif result["status"] == "failed":
        scan.message = result.get("coverage", {}).get("notes") or "Scan failed"
        scan.message = scan.message[:180]
    else:
        scan.message = "Scan completed"
    scan.completed_at = datetime.now(timezone.utc)
    scan.result_json = json.dumps(result)
    scan.findings.clear()
    db.flush()
    for item in result.get("findings", []):
        db.add(
            Finding(
                scan_id=scan.id,
                finding_id=item["finding_id"],
                title=item["title"],
                severity=item["severity"],
                confidence=item.get("confidence", "medium"),
                status=item.get("status", "open"),
                detection_type=item.get("detection_type", "catalog"),
                location=item.get("location"),
                cwe=item.get("cwe"),
                owasp_id=item["owasp"]["id"],
                owasp_name=item["owasp"]["name"],
                nist=item.get("nist"),
                sans=item.get("sans"),
                description=item.get("description", ""),
                evidence=item.get("evidence"),
                recommendation=item.get("recommendation", ""),
            )
        )


def _historical_scan(
    db: Session,
    *,
    case: Case,
    target_id: str,
    target_url: str,
    days_ago: int,
    drop_ids: set[str] | None = None,
) -> None:
    catalog = load_catalog(target_id)
    started = datetime.now(timezone.utc) - timedelta(days=days_ago)
    findings = list(catalog["findings"])
    if drop_ids:
        findings = [f for f in findings if f["finding_id"] not in drop_ids]
    scan = Scan(
        id=f"scn-{target_id}-{days_ago}d",
        case_id=case.id,
        target_name=catalog["target_name"],
        target_url=target_url,
        status="completed",
        progress=100,
        message="Historical demo scan",
        started_at=started,
        completed_at=started + timedelta(minutes=2),
    )
    db.add(scan)
    db.flush()
    result = build_scan_result(
        scan_id=scan.id,
        case_id=case.id,
        target_name=catalog["target_name"],
        target_url=target_url,
        started_at=started,
        findings=findings,
        tech_stack=list(catalog.get("tech_stack") or []),
        modes=["catalog"],
        out_of_scope=list(catalog.get("out_of_scope") or ["A04:2021 Insecure Design"]),
        notes=(
            catalog.get("coverage_notes", "")
            + " Seeded history (no live probe)."
        ).strip(),
        live_check={
            "reachable": False,
            "error": "seeded history (no live probe)",
            "missing_headers": [],
            "status_code": None,
        },
        completed_at=started + timedelta(minutes=2),
    )
    result["started_at"] = started.isoformat()
    result["completed_at"] = (started + timedelta(minutes=2)).isoformat()
    persist_result(db, scan, result)
    scan.started_at = started
    scan.completed_at = started + timedelta(minutes=2)


def seed_if_empty(db: Session) -> None:
    if db.query(User).first():
        return

    analyst = User(
        id=DEMO_USER_ID,
        name="Avery Chen",
        email="avery.chen@webset.local",
        role="analyst",
    )
    instructor = User(
        id="usr-instructor-01",
        name="Sam Okonkwo",
        email="sam.okonkwo@webset.local",
        role="instructor",
    )
    db.add_all([analyst, instructor])

    juice_case = Case(
        id="CASE-2026-001",
        title="Juice Shop — teaching lab baseline",
        application="OWASP Juice Shop",
        owner_id=analyst.id,
        notes="Repeatable scan of the local Juice Shop container for the capstone demo.",
    )
    dvwa_case = Case(
        id="CASE-2026-002",
        title="DVWA — PHP stack lab",
        application="DVWA",
        owner_id=instructor.id,
        notes="Second authorised target. Used to show multi-stack case management.",
    )
    db.add_all([juice_case, dvwa_case])
    db.flush()

    _historical_scan(
        db,
        case=juice_case,
        target_id="juice-shop",
        target_url="http://localhost:3000",
        days_ago=14,
    )
    _historical_scan(
        db,
        case=juice_case,
        target_id="juice-shop",
        target_url="http://localhost:3000",
        days_ago=3,
        drop_ids={"WEBSET-JS-010"},
    )
    _historical_scan(
        db,
        case=dvwa_case,
        target_id="dvwa",
        target_url="http://localhost:8081",
        days_ago=7,
    )
    db.commit()


def new_ids():
    return str(uuid4())
