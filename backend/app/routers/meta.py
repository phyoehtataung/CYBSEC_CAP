from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import DEMO_TARGETS
from ..database import get_db
from ..models import User
from ..serializers import dashboard_payload

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/health")
def health():
    return {"status": "ok", "product": "WebSET"}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    return dashboard_payload(db)


@router.get("/targets")
def targets():
    return {"targets": DEMO_TARGETS}


@router.get("/users")
def users(db: Session = Depends(get_db)):
    rows = db.query(User).all()
    return {
        "users": [
            {"id": u.id, "name": u.name, "email": u.email, "role": u.role}
            for u in rows
        ]
    }
