import logging
import os
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import update
from ..services.attack_runner import AttackRunner
from ..celery_app import celery_app
from ..database import SessionLocal
from ..models import Scan, AuditLog
from ..services.scan_control import ScanCancelled

logger = logging.getLogger(__name__)


@celery_app.task(name="sentinel.run_scan")
def run_scan(scan_id: str):
    id = UUID(scan_id)
    with SessionLocal() as db:
        # Atomic compare-and-set, including on SQLite. Duplicate deliveries cannot
        # both claim the same queued job.
        claimed = db.execute(update(Scan).where(Scan.id == id, Scan.status == "queued")
            .values(status="running", started_at=datetime.now(timezone.utc)))
        if claimed.rowcount != 1:
            db.rollback()
            if db.get(Scan, id) is None:
                raise ValueError(f"Scan not found: {scan_id}")
            return {"scan_id": scan_id, "skipped": True}
        scan = db.get(Scan, id)
        target_id = scan.target_id
        pipeline = scan.configuration.pipeline if scan.configuration else os.environ.get("SENTINEL_PIPELINE", "week1")
        db.add(AuditLog(action="scan.running", scan_id=id, resource_id=str(id), details={}))
        db.commit()
        try:
            if pipeline == "week34":
                from ..services.week34_runner import Week34AttackRunner
                runner = Week34AttackRunner()
            elif pipeline == "week2":
                from ..services.week2_runner import Week2AttackRunner
                runner = Week2AttackRunner()
            elif pipeline == "week1":
                runner = AttackRunner()
            else:
                raise ValueError("Unsupported SENTINEL_PIPELINE")
            result = runner.run(id, target_id)
            # Cancellation wins over late completion from an in-flight tool call.
            changed = db.execute(update(Scan).where(Scan.id == id, Scan.status == "running")
                .values(status="completed", finished_at=datetime.now(timezone.utc)))
            if changed.rowcount:
                db.add(AuditLog(action="scan.completed", scan_id=id, resource_id=str(id), details={}))
            db.commit()
            return result
        except ScanCancelled:
            db.rollback()
            return {"scan_id": scan_id, "cancelled": True}
        except Exception:
            db.rollback()
            changed = db.execute(update(Scan).where(Scan.id == id, Scan.status == "running")
                .values(status="failed", error_code="execution_failed", finished_at=datetime.now(timezone.utc)))
            if changed.rowcount:
                db.add(AuditLog(action="scan.failed", scan_id=id, resource_id=str(id), details={"code": "execution_failed"}))
            db.commit()
            logger.exception("Scan failed: %s", scan_id)
            raise
