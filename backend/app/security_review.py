from uuid import UUID

from sqlalchemy.orm import Session
from security_validation.src.pipeline import validate_backend_execution

from .models import AttackAttempt, Response


def review_stored_response(
    db: Session,
    *,
    attempt_id: UUID,
    response_id: UUID,
    test_case_id: str,
    trusted_fixture: dict,
    finding_id: UUID,
) -> dict:
    attempt = db.get(AttackAttempt, attempt_id)
    response = db.get(Response, response_id)

    if attempt is None or response is None:
        raise ValueError("Stored attempt or response not found")

    return validate_backend_execution(
        attempt={
            "id": str(attempt.id),
            "scan_id": str(attempt.scan_id),
            "attack_case_id": attempt.attack_case_id,
            "payload": attempt.payload,
            "status": attempt.status,
        },
        response={
            "attack_attempt_id": str(response.attack_attempt_id),
            "content": response.content,
        },
        test_case_id=test_case_id,
        trusted_fixture=trusted_fixture,
        finding_id=str(finding_id),
    )