"""Canonical-backend adapter for suspected findings, not a second SQL schema.

The caller must first persist the response and supply its UUID. Session
transaction ownership stays with the backend (no implicit commits).
"""
from sqlalchemy.orm import Session
from attack_engine.backend_contract import as_uuid, normalize_category
from attack_engine.finding import Finding as AttackFinding


class FindingRepository:
    def __init__(self, db: Session, *, response_id):
        self.db = db
        self.response_id = as_uuid(response_id, "response_id")

    def save(self, finding: AttackFinding):
        from app.models import Response, Finding
        if self.db.get(Response, self.response_id) is None:
            raise ValueError("Response not found")
        if not isinstance(finding.evidence, str) or not finding.evidence.strip():
            raise ValueError("Finding evidence must be non-empty")
        stored = Finding(
            response_id=self.response_id,
            category=normalize_category(finding.category),
            severity="unassessed",
            status="suspected",
            evidence=finding.evidence,
        )
        self.db.add(stored)
        self.db.flush()
        return stored
