import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..models import Case, Scan
from ..scanner.allowlist import TargetNotAllowed, validate_local_target
from ..scanner.engine import run_scan
from ..seed import persist_result
from ..serializers import scan_to_detail, scan_to_summary

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanIn(BaseModel):
    case_id: str
    target_id: str | None = None
    target_name: str = Field(default="Local lab target", max_length=80)
    target_url: str = Field(min_length=8, max_length=200)


def _execute_scan(scan_id: str, payload: dict) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.progress = 15
        scan.message = "Checking local allow-list"
        db.commit()

        steps = [
            (35, "Fingerprinting the local target"),
            (55, "Reviewing response headers"),
            (75, "Loading training-app catalog"),
            (90, "Normalising findings to the WebSET schema"),
        ]
        for progress, message in steps:
            scan.progress = progress
            scan.message = message
            db.commit()
            # Tiny pause so the dashboard can show progress during the demo.
            asyncio.run(asyncio.sleep(0.45))

        result = run_scan(
            scan_id=scan.id,
            case_id=scan.case_id,
            target_name=payload["target_name"],
            target_url=payload["target_url"],
            target_id=payload.get("target_id"),
        )
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
    except Exception as exc:  # noqa: BLE001 — demo scanner should never crash the API
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.progress = 100
            scan.message = f"Scanner error: {exc}"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
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
