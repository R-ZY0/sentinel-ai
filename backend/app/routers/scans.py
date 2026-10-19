from uuid import UUID
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from kombu.exceptions import OperationalError
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan, Target
from ..scan_tasks import run_scan
from ..schemas import ScanCreate, ScanRead

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    if db.get(Target, payload.target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(target_id=payload.target_id, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        run_scan.apply_async(args=[str(scan.id)], retry=False)

    except OperationalError:
        logger.exception("Scan job submission failed: scan=%s", scan.id)
        db.refresh(scan)

        if scan.status == "queued":
            scan.status = "failed"
            db.commit()

        raise HTTPException(
            status_code=503,
            detail={
                "message": "Could not confirm scan job submission",
                "scan_id": str(scan.id),
            },
        )
    logger.info("Scan job submitted: scan=%s", scan.id)
    db.refresh(scan)
    return scan


@router.get("/{id}", response_model=ScanRead)
def get_scan(id: UUID, db: Session = Depends(get_db)):
    scan = db.get(Scan, id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan