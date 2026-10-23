"""Persistence boundary: AttackRun -> Attempt -> Response -> Finding.

The caller owns commit/rollback; heuristic findings are suspected by default.
"""
from uuid import uuid4
from sqlalchemy.orm import Session
from attack_engine.backend_contract import attack_run_to_backend_records, as_uuid
from .models import AttackAttempt, Response, Finding, Scan


def persist_attack_run(
    db: Session, *, scan_id, attack, finding_evidence: str | None = None,
    confirmed: bool = False,
) -> dict:
    scan_uuid = as_uuid(scan_id, "scan_id")
    if db.get(Scan, scan_uuid) is None:
        raise ValueError("Scan not found")
    mapped = attack_run_to_backend_records(
        attack, scan_id=scan_uuid, attempt_id=uuid4()
    )
    if finding_evidence is not None:
        if mapped.response is None:
            raise ValueError("Cannot add a finding without a completed response")
        if not isinstance(finding_evidence, str) or not finding_evidence.strip():
            raise ValueError("Finding evidence must be non-empty text")
    attempt = AttackAttempt(**mapped.attempt)
    db.add(attempt)
    db.flush()
    response = None
    finding = None
    if mapped.response is not None:
        response = Response(**mapped.response)
        db.add(response)
        db.flush()
        if finding_evidence is not None:
            finding = Finding(
                response_id=response.id,
                category=attempt.category,
                severity="unassessed",
                status="confirmed" if confirmed else "suspected",
                evidence=finding_evidence,
            )
            db.add(finding)
            db.flush()
    return {
        "attempt_id": attempt.id,
        "response_id": response.id if response is not None else None,
        "finding_id": finding.id if finding is not None else None,
        "attack_case_id": attempt.attack_case_id,
    }
