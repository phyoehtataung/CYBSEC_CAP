import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..models import Case, Finding, Scan
from ..scanner.allowlist import TargetNotAllowed, validate_local_target
from ..scanner.engine import run_scan
from ..seed import persist_result
from ..serializers import finding_to_dict, scan_to_detail, scan_to_summary

router = APIRouter(prefix="/api/scans", tags=["scans"])

_cancel_flags: dict[str, bool] = {}


class ScanIn(BaseModel):
    case_id: str
    target_id: str | None = None
    target_name: str = Field(default="Local lab target", max_length=80)
    target_url: str = Field(min_length=8, max_length=200)


class FindingPatch(BaseModel):
    status: str = Field(pattern="^(open|accepted|false_positive)$")


def request_cancel(scan_id: str) -> None:
    _cancel_flags[scan_id] = True


def _execute_scan(scan_id: str, payload: dict) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        if _cancel_flags.get(scan_id):
            scan.status = "cancelled"
            scan.progress = 100
            scan.message = "Scan cancelled"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        scan.status = "running"
        scan.progress = 8
        scan.message = "Starting scanner"
        db.commit()

        def on_progress(pct: int, message: str) -> None:
            row = db.get(Scan, scan_id)
            if not row:
                request_cancel(scan_id)
                return
            row.status = "running"
            row.progress = pct
            row.message = message
            db.commit()

        result = run_scan(
            scan_id=scan.id,
            case_id=scan.case_id,
            target_name=payload["target_name"],
            target_url=payload["target_url"],
            target_id=payload.get("target_id"),
            progress=on_progress,
            cancelled=lambda: _cancel_flags.get(scan_id, False),
        )
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        persist_result(db, scan, result)
        db.commit()
    except TargetNotAllowed as exc:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "blocked"
            scan.progress = 100
            scan.message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — scanner should never crash the API
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.progress = 100
            scan.message = f"Scanner error: {exc}"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        _cancel_flags.pop(scan_id, None)
        db.close()


@router.get("")
def list_scans(case_id: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Scan).order_by(Scan.started_at.desc())
    if case_id:
        query = query.filter(Scan.case_id == case_id)
    return {"scans": [scan_to_summary(s) for s in query.all()]}


@router.post("")
def start_scan(payload: ScanIn, background: BackgroundTasks, db: Session = Depends(get_db)):
    case = db.get(Case, payload.case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    try:
        url = validate_local_target(payload.target_url)
    except TargetNotAllowed as exc:
        raise HTTPException(400, str(exc)) from exc

    scan = Scan(
        id=f"scn-{uuid4().hex[:10]}",
        case_id=case.id,
        target_name=payload.target_name,
        target_url=url,
        status="queued",
        progress=5,
        message="Queued",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    background.add_task(
        _execute_scan,
        scan.id,
        {
            "target_name": payload.target_name,
            "target_url": url,
            "target_id": payload.target_id,
        },
    )
    return scan_to_summary(scan)


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan_to_detail(scan)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status not in {"queued", "running"}:
        raise HTTPException(409, "Scan is not running")
    request_cancel(scan_id)
    scan.message = "Cancellation requested"
    db.commit()
    return scan_to_summary(scan)


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in {"queued", "running"}:
        request_cancel(scan_id)
    db.delete(scan)
    db.commit()
    return {"ok": True, "scan_id": scan_id}


@router.patch("/{scan_id}/findings/{finding_id}")
def triage_finding(scan_id: str, finding_id: str, payload: FindingPatch, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    row = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.finding_id == finding_id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Finding not found")
    row.status = payload.status
    try:
        result = json.loads(scan.result_json or "{}")
    except json.JSONDecodeError:
        result = {}
    for item in result.get("findings") or []:
        if item.get("finding_id") == finding_id:
            item["status"] = payload.status
    scan.result_json = json.dumps(result)
    db.commit()
    db.refresh(row)
    return finding_to_dict(row)
