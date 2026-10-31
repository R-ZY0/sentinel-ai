import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AttackAttempt, Finding, Response, ResponseEvaluation


def store_evaluation(
    db: Session,
    *,
    response_id: UUID,
    baseline_results: dict,
    security_result: dict,
) -> ResponseEvaluation:
    existing = db.scalar(
        select(ResponseEvaluation).where(
            ResponseEvaluation.response_id == response_id
        )
    )
    if existing is not None:
        if (
            existing.baseline_results != baseline_results
            or existing.security_result != security_result
        ):
            raise ValueError("Response already has a different evaluation")
        return existing

    response = db.get(Response, response_id)
    if response is None:
        raise ValueError("Response not found")

    attempt = db.get(AttackAttempt, response.attack_attempt_id)
    document = security_result["finding"]
    validation = security_result["validation"]

    if document["scan_id"] != str(attempt.scan_id):
        raise ValueError("Finding belongs to a different scan")
    if baseline_results["attack_id"] != attempt.attack_case_id:
        raise ValueError("Baseline results belong to a different attack")
    if any(
        item["attempt_id"] != str(attempt.id)
        for item in document["evidence"]
    ):
        raise ValueError("Evidence belongs to a different attempt")

    evaluation = ResponseEvaluation(
        response_id=response_id,
        baseline_results=baseline_results,
        security_result=security_result,
    )
    db.add(evaluation)

    if validation["verdict"] == "LEAK":
        if document["status"] != "confirmed":
            raise ValueError("Leak verdict requires a confirmed document")

        db.add(Finding(
            id=UUID(document["finding_id"]),
            response_id=response_id,
            category=document["category"],
            severity="unassessed",
            status="confirmed",
            evidence=json.dumps(document["evidence"]),
        ))

    db.flush()
    return evaluation