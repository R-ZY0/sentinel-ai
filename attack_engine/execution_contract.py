"""Non-breaking export contract for AttackRun records."""

from dataclasses import asdict
from datetime import datetime
from uuid import uuid4

from attack_engine.attack_run import AttackRun


def export_attack_run(
    attack: AttackRun,
    *,
    scan_id: str,
    target_id: str,
    execution_id: str | None = None,
) -> dict:
    """Export a run with explicitly supplied team identifiers."""

    if not scan_id or not scan_id.strip():
        raise ValueError("scan_id is required")
    if not target_id or not target_id.strip():
        raise ValueError("target_id is required")

    result = asdict(attack)
    result["execution_id"] = execution_id or str(uuid4())
    result["scan_id"] = scan_id
    result["target_id"] = target_id

    timestamp = result.get("timestamp")
    if isinstance(timestamp, datetime):
        result["timestamp"] = timestamp.isoformat()

    return result
