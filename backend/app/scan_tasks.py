import logging
from uuid import UUID

from .attack_runner import AttackRunner
from .celery_app import celery_app
from .database import SessionLocal
from .models import Scan

logger = logging.getLogger(__name__)


@celery_app.task(name="sentinel.run_scan")
def run_scan(scan_id: str):
    with SessionLocal() as db:
        scan = db.get(Scan, UUID(scan_id), with_for_update=True)

        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        if scan.status != "queued":
            db.rollback()
            return {"scan_id": scan_id, "skipped": True}

        target_id = scan.target_id
        scan.status = "running"
        db.commit()

        try:
            result = AttackRunner().run(UUID(scan_id), target_id)

            db.refresh(scan)
            scan.status = "completed"
            db.commit()
            return result

        except Exception:
            db.rollback()
            db.refresh(scan)
            scan.status = "failed"
            db.commit()
            logger.exception("Scan failed: %s", scan_id)
            raise