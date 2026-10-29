"""Cyber #2 read-only integration boundary for Backend AttackAttempt/Response.

No DB persistence or network calls. Trust assertions MUST come from the
authorized server-side harness, not a caller-provided API payload or model.
"""
from .adapter import from_backend_records
from .validator import validate_response
from .finding import build_finding


def validate_backend_execution(
    *,
    attempt: dict,
    response: dict | None,
    test_case_id: str,
    trusted_fixture: dict,
    finding_id: str,
) -> dict:
    """Build independent validation and schema-checked Finding in one operation.

    The stable Backend attack_case_id (e.g. SPL-001) is *not* the TC-00x ID.
    The trusted caller is responsible for associating them correctly,
    checking the target authorization, and establishing fixture provenance.
    This function NEVER inserts a Finding into the database.
    """
    attack_run, target_response = from_backend_records(
        attempt, response, test_case_id=test_case_id
    )
    validation = validate_response(
        attack_run, target_response, trusted_fixture=trusted_fixture
    )
    finding = build_finding(
        attack_run, validation, finding_id=finding_id
    )
    return {"validation": validation, "finding": finding}
