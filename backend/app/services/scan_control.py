from sqlalchemy import select
from ..models import Scan


class ScanCancelled(Exception):
    pass


def lock_scan_for_write(db, scan_id):
    """Serialize a result commit against cancellation on PostgreSQL.

    SQLite serializes writers itself. Keep this lock through the caller's commit.
    """
    state = db.scalar(select(Scan.status).where(Scan.id == scan_id).with_for_update())
    if state == "cancelled":
        raise ScanCancelled("Scan was cancelled")


def cancellation_checkpoint(sessions, scan_id):
    with sessions() as db:
        state = db.scalar(select(Scan.status).where(Scan.id == scan_id))
        if state == "cancelled":
            raise ScanCancelled("Scan was cancelled")
