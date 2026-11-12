import logging
from uuid import UUID, uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response as HttpResponse
from kombu.exceptions import OperationalError
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan, Target, User, ScanConfiguration, ScanAttack
from ..tasks.scans import run_scan
from ..schemas import ScanCreate, ScanRead
from ..dependencies import get_current_user
from ..services.access import visible_to, require_visible
from ..services.audit import audit
from ..services.attack_catalog import select_attacks
from ..services.target_adapters import require_scan_compatible, TargetAdapterError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"], dependencies=[Depends(get_current_user)])


def find_scan(db, id, user):
    return require_visible(db.get(Scan, id), user, "Scan")


def queue_scan(db, scan, user):
    target = require_visible(db.scalar(select(Target).where(Target.id == scan.target_id).with_for_update()), user, "Target")
    try:
        require_scan_compatible(target)
    except TargetAdapterError as exc:
        raise HTTPException(409, str(exc)) from None
    if scan.configuration:
        if scan.configuration.pipeline == "week34":
            from ..services.receipts import audit_key
            try:
                audit_key()
            except ValueError:
                raise HTTPException(503, "Week 3-4 evidence signing is not configured on the server") from None
        snapshot = scan.configuration.target_snapshot
        if snapshot != target_snapshot(target):
            raise HTTPException(409, "Target changed after scan creation; create a new scan")
    job_id = str(uuid4())
    claimed = db.execute(update(Scan).where(Scan.id == scan.id, Scan.status == "created")
        .values(status="queued", task_id=job_id))
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Only a created scan can be started")
    audit(db, "scan.queued", scan.id, user=user, scan_id=scan.id)
    db.commit()
    db.refresh(scan)
    try:
        run_scan.apply_async(args=[str(scan.id)], task_id=job_id, retry=False)
    except OperationalError:
        logger.exception("Scan job submission failed: scan=%s", scan.id)
        db.execute(update(Scan).where(Scan.id == scan.id, Scan.status == "queued")
            .values(status="failed", error_code="queue_submission_failed", finished_at=datetime.now(timezone.utc)))
        audit(db, "scan.queue_failed", scan.id, user=user, scan_id=scan.id)
        db.commit()
        raise HTTPException(503, {"message": "Could not confirm scan job submission", "scan_id": str(scan.id)})
    db.refresh(scan)
    return scan


def target_snapshot(target):
    return {"endpoint": target.endpoint, "target_type": target.target_type,
            "configuration": target.configuration or {}, "authorized": target.authorized}


@router.post("", response_model=ScanRead, status_code=201)
def create_scan(payload: ScanCreate, response: HttpResponse, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = require_visible(db.get(Target, payload.target_id), user, "Target")
    try:
        require_scan_compatible(target)
        attacks = select_attacks(db, payload.configuration)
    except (TargetAdapterError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from None
    scan = Scan(target_id=target.id, owner_id=user.id, status="created")
    db.add(scan)
    db.flush()
    configuration = ScanConfiguration(scan_id=scan.id, pipeline=payload.configuration.pipeline,
        engines=payload.configuration.engines, target_snapshot=target_snapshot(target))
    db.add(configuration)
    db.flush()
    for position, attack in enumerate(attacks):
        db.add(ScanAttack(configuration_id=configuration.id, attack_id=attack.id, position=position,
            definition=definition_snapshot(attack)))
    audit(db, "scan.created", scan.id, user=user, scan_id=scan.id)
    db.commit()
    db.refresh(scan)
    if payload.auto_start:
        response.status_code = 202
        return queue_scan(db, scan, user)
    return scan


def definition_snapshot(attack):
    from ..services.week34_scenarios import CASE_BY_ATTACK
    from attack_engine.normalized_attack_library import NORMALIZED_ATTACK_LIBRARY
    definition = {key: getattr(attack, key) for key in
                  ("id", "category", "engine", "payload", "strategy", "expected_behavior")}
    normalized = next((item for item in NORMALIZED_ATTACK_LIBRARY if item.attack_id == attack.id), None)
    if normalized:
        definition["normalized_definition"] = normalized.to_dict()
    definition["test_case_id"] = CASE_BY_ATTACK.get(attack.id)
    return definition


@router.get("", response_model=list[ScanRead])
def list_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user),
               offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
               status: str | None = None, target_id: UUID | None = None):
    query = select(Scan).where(visible_to(Scan, user))
    if status is not None:
        if status not in {"created", "queued", "running", "completed", "failed", "cancelled"}:
            raise HTTPException(422, "Unsupported scan status")
        query = query.where(Scan.status == status)
    if target_id:
        query = query.where(Scan.target_id == target_id)
    return db.scalars(query.order_by(Scan.created_at.desc(), Scan.id).offset(offset).limit(limit)).all()


@router.get("/{id}", response_model=ScanRead)
def get_scan(id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return find_scan(db, id, user)


@router.post("/{id}/start", response_model=ScanRead, status_code=202)
def start_scan(id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return queue_scan(db, find_scan(db, id, user), user)


@router.post("/{id}/cancel", response_model=ScanRead)
def cancel_scan(id: UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = find_scan(db, id, user)
    if scan.status == "cancelled":
        return scan
    changed = db.execute(update(Scan).where(Scan.id == id, Scan.status.in_(["created", "queued", "running"]))
        .values(status="cancelled", finished_at=datetime.now(timezone.utc)))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "A finished scan cannot be cancelled")
    audit(db, "scan.cancelled", id, user=user, scan_id=id)
    db.commit()
    db.refresh(scan)
    return scan
