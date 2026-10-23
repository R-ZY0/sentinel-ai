"""Backend-shaped records for authorized AttackRun integration.

This module prepares data; it does not persist to the database.
The backend remains responsible for transactions, findings and IDs.
"""

from dataclasses import dataclass
from uuid import UUID

from attack_engine.attack_run import AttackRun


def as_uuid(value, name):
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise ValueError(f"{name} must be a valid UUID") from None


def normalize_category(category):
    return category.strip().lower().replace(" ", "_")


@dataclass(frozen=True)
class BackendRecords:
    attempt: dict
    response: dict | None


def attack_run_to_backend_records(
    attack: AttackRun,
    *,
    scan_id,
    attempt_id,
    target_id=None,
) -> BackendRecords:
    """Map an AttackRun to the backend's existing record shapes.

    attempt_id must come from the actual AttackAttempt record.
    target_id is optional and belongs to Scan, not AttackAttempt.
    """
    scan_uuid = as_uuid(scan_id, "scan_id")
    attempt_uuid = as_uuid(attempt_id, "attempt_id")

    if target_id is not None:
        as_uuid(target_id, "target_id")

    if not attack.attack_id or not attack.attack_id.strip():
        raise ValueError("attack_id is required")

    if not attack.payload or not attack.payload.strip():
        raise ValueError("payload is required")

    if attack.status not in {"pending", "running", "completed", "failed"}:
        raise ValueError("Unsupported execution status")

    attempt = {
        "id": attempt_uuid,
        "scan_id": scan_uuid,
        "attack_id": attack.attack_id,
        "category": normalize_category(attack.category),
        "payload": attack.payload,
        "status": attack.status,
    }

    response = None

    if attack.status == "completed":
        if not isinstance(attack.actual_response, str):
            raise ValueError(
                "Completed attack requires an actual response"
            )
        if not attack.actual_response.strip():
            raise ValueError(
                "Completed attack response must not be empty"
            )

        response = {
            "attack_attempt_id": attempt_uuid,
            "content": attack.actual_response,
        }

    return BackendRecords(
        attempt=attempt,
        response=response,
    )
