from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Case, User
from ..seed import DEMO_USER_ID
from ..serializers import case_to_dict

router = APIRouter(prefix="/api/cases", tags=["cases"])


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    application: str = Field(min_length=2, max_length=80)
    notes: str = ""
    owner_id: str | None = None


@router.get("")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    return {"cases": [case_to_dict(c) for c in cases]}


@router.post("")
def create_case(payload: CaseIn, db: Session = Depends(get_db)):
    owner_id = payload.owner_id or DEMO_USER_ID
    owner = db.get(User, owner_id)
    if not owner:
        raise HTTPException(400, "Unknown owner profile")
    case = Case(
        id=f"CASE-{datetime.now(timezone.utc).year}-{uuid4().hex[:6].upper()}",
        title=payload.title,
        application=payload.application,
        owner_id=owner.id,
        notes=payload.notes,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case_to_dict(case)


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case_to_dict(case)
