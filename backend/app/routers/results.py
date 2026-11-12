"""Ownership-scoped retrieval of the completed pipeline and evidence receipt."""
from uuid import UUID
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..dependencies import get_current_user
from ..models import Scan, User, AttackAttempt, Response, ResponseEvaluation, EvidenceReceipt
from ..services.access import require_visible
from ..services.receipts import stored_receipt_integrity
from ..services.audit import audit

router = APIRouter(prefix="/scans", tags=["Scan results"])


@router.get("/{id}/results")
def results(id: UUID, include_raw: bool = False, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_visible(db.get(Scan, id), user, "Scan")
    records = db.execute(select(AttackAttempt, Response, ResponseEvaluation, EvidenceReceipt)
        .outerjoin(Response, Response.attack_attempt_id == AttackAttempt.id)
        .outerjoin(ResponseEvaluation, ResponseEvaluation.response_id == Response.id)
        .outerjoin(EvidenceReceipt, EvidenceReceipt.response_id == Response.id)
        .where(AttackAttempt.scan_id == id).order_by(AttackAttempt.created_at, AttackAttempt.id)).all()
    output = []
    for attempt, response, evaluation, receipt in records:
        metadata = attempt.execution_metadata or {}
        integrity = None
        if receipt and evaluation:
            try:
                integrity = stored_receipt_integrity(receipt, attempt, response, evaluation.security_result)
            except (ValueError, TypeError, KeyError):
                integrity = "unavailable"
        output.append({"attempt_id": str(attempt.id), "attack_id": attempt.attack_case_id,
            "catalog_attack_id": attempt.attack_id, "test_case_id": attempt.test_case_id,
            "status": attempt.status, "execution": metadata,
            "target_response": {"response_id": str(response.id),
                "content": response.content if include_raw else metadata.get("redacted_response", "[Legacy response omitted]"),
                "timestamp": response.created_at, "status": attempt.status,
                "target_id": str(db.get(Scan, id).target_id), "latency_ms": metadata.get("latency_ms"),
                "latency_scope": metadata.get("latency_scope"), "attack_id": attempt.attack_case_id} if response else None,
            "comparison": evaluation.baseline_results if evaluation else None,
            "security": evaluation.security_result if evaluation else None,
            "receipt_integrity": integrity})
    audit(db, "scan.results_read", id, user=user, scan_id=id, include_raw=include_raw)
    db.commit()
    return {"scan_id": str(id), "results": output}
