import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from ..config import TEMPLATE_DIR
from ..database import get_db
from ..models import Scan
from ..serializers import scan_to_detail

router = APIRouter(prefix="/api/scans", tags=["reports"])

env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)


@router.get("/{scan_id}/report.json")
def report_json(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    payload = scan_to_detail(scan)
    return JSONResponse(
        payload,
        headers={
            "Content-Disposition": f'attachment; filename="{scan_id}.json"'
        },
    )


@router.get("/{scan_id}/report.html")
def report_html(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    payload = scan_to_detail(scan)
    template = env.get_template("report.html")
    html = template.render(scan=payload, raw=json.dumps(payload, indent=2))
    return HTMLResponse(
        html,
        headers={
            "Content-Disposition": f'attachment; filename="{scan_id}.html"'
        },
    )
