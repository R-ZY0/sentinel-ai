from datetime import datetime, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Response, status, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..dependencies import get_current_user
from ..models import Scan, Target, User
from ..schemas import TargetCreate, TargetRead, TargetValidationRead
from ..services.access import visible_to, require_visible
from ..services.audit import audit
from ..services.target_adapters import get_target_adapter, TargetAdapterError

router = APIRouter(prefix="/targets", tags=["Targets"], dependencies=[Depends(get_current_user)])


def find_target(db, id, user):
    return require_visible(db.scalar(select(Target).where(Target.id == id).with_for_update()), user, "Target")


def apply_target(target, payload):
    target.name = payload.name
    target.endpoint = str(payload.endpoint)
    target.target_type = payload.target_type
    target.configuration = payload.configuration.model_dump(exclude_none=True)
    target.authorized = payload.authorized
    target.validation_status = "not_validated"
    target.validated_at = None


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = Target(owner_id=user.id)
    apply_target(target, payload)
    db.add(target)
    db.flush()
    audit(db, "target.created", target.id, user=user)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=list[TargetRead])
def list_targets(db: Session = Depends(get_db), user: User = Depends(get_current_user),
                 offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
    return db.scalars(select(Target).where(visible_to(Target, user))
        .order_by(Target.created_at, Target.id).offset(offset).limit(limit)).all()


@router.get("/{id}", response_model=TargetRead)
def get_target(id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return find_target(db, id, user)


@router.put("/{id}", response_model=TargetRead)
def update_target(id: UUID, payload: TargetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = find_target(db, id, user)
    if db.scalar(select(Scan.id).where(Scan.target_id == id, Scan.status.in_(["queued", "running"])).limit(1)):
        raise HTTPException(409, "Cannot update a target while a scan is active")
    apply_target(target, payload)
    audit(db, "target.updated", id, user=user)
    db.commit()
    db.refresh(target)
    return target


@router.post("/{id}/validate", response_model=TargetValidationRead)
def validate_target(id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = find_target(db, id, user)
    latency = None
    try:
        reply = get_target_adapter(target).respond("Reply with OK. This is a connectivity check.")
        outcome, message, latency = "valid", "Target returned a usable response", reply.latency_ms
    except TargetAdapterError as exc:
        outcome, message = "invalid", str(exc)
    checked_at = datetime.now(timezone.utc)
    target.validation_status, target.validated_at = outcome, checked_at
    audit(db, "target.validated", id, user=user, status=outcome)
    db.commit()
    return TargetValidationRead(target_id=id, status=outcome, message=message, latency_ms=latency, checked_at=checked_at)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_target(id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = find_target(db, id, user)
    if db.scalar(select(Scan.id).where(Scan.target_id == id).limit(1)) is not None:
        raise HTTPException(409, "Cannot delete a target with scan history")
    audit(db, "target.deleted", id, user=user)
    db.delete(target)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
