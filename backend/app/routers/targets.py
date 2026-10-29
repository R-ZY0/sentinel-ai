from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan,Target
from ..dependencies import get_current_user
from ..schemas import TargetCreate, TargetRead
from uuid import UUID

router = APIRouter(
    prefix="/targets",
    tags=["Targets"],
    dependencies=[Depends(get_current_user)],
)


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


@router.get("/{id}", response_model=TargetRead)
def get_target(id: UUID, db: Session = Depends(get_db)):
    target = db.get(Target, id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{id}", response_model=TargetRead)
def update_target(
    id: UUID,
    payload: TargetCreate,
    db: Session = Depends(get_db),
):
    target = db.get(Target, id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    target.name = payload.name
    target.endpoint = str(payload.endpoint)

    db.commit()
    db.refresh(target)
    return target

@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def delete_target(id: UUID, db: Session = Depends(get_db)):
    target = db.get(Target, id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    existing_scan = db.scalar(
        select(Scan.id).where(Scan.target_id == id).limit(1)
    )
    if existing_scan is not None:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete a target with scan history",
        )

    db.delete(target)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)