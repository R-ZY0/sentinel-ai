from ..models import AuditLog


def audit(db, action, resource_id, *, user=None, scan_id=None, **details):
    db.add(AuditLog(
        actor_id=user.id if user else None, scan_id=scan_id,
        action=action, resource_id=str(resource_id), details=details,
    ))
