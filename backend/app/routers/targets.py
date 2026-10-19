from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Target
from ..schemas import TargetCreate, TargetRead

router = APIRouter(prefix="/targets", tags=["Targets"])


@router.post(
    "",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    target = Target(
        name=payload.name,
        endpoint=str(payload.endpoint),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=list[TargetRead])
def list_targets(db: Session = Depends(get_db)):
    return db.scalars(
        select(Target).order_by(Target.created_at, Target.id)
    ).all()