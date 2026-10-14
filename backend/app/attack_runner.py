import logging
from uuid import UUID

from .attack_engine import AttackEngine
from .database import SessionLocal
from .judge import CanaryJudge
from .local_target import LocalTarget, OLLAMA_BASE_URL
from .models import AttackAttempt, Finding, Response, Target

logger = logging.getLogger(__name__)


class AttackRunner:
    def run(self, scan_id: UUID, target_id: UUID) -> dict:
        with SessionLocal() as db:
            target = db.get(Target, target_id)
            if target is None:
                raise ValueError("Target not found")

            if target.endpoint.rstrip("/") != OLLAMA_BASE_URL:
                raise ValueError(
                    "This first runner supports only the configured local Ollama target"
                )

        results = []

        for probe in AttackEngine().probes():
            with SessionLocal() as db:
                attempt = AttackAttempt(
                    scan_id=scan_id,
                    category=probe.category,
                    payload=probe.payload,
                    status="running",
                )
                db.add(attempt)
                db.flush()
                attempt_id = attempt.id
                db.commit()

                try:
                    response_text = LocalTarget().respond(probe.payload)
                    verdict = CanaryJudge().evaluate(response_text)

                    response = Response(
                        attack_attempt_id=attempt_id,
                        content=response_text,
                    )
                    db.add(response)
                    db.flush()
                    response_id = response.id

                    finding_id = None
                    if verdict.leaked:
                        finding = Finding(
                            response_id=response_id,
                            category=probe.category,
                            severity="unassessed",
                            status="confirmed",
                            evidence=verdict.evidence,
                        )
                        db.add(finding)
                        db.flush()
                        finding_id = finding.id

                    attempt.status = "completed"
                    db.commit()

                    logger.info(
                        "Probe completed: scan=%s attempt=%s leaked=%s",
                        scan_id,
                        attempt_id,
                        verdict.leaked,
                    )

                    results.append({
                        "attempt_id": str(attempt_id),
                        "response_id": str(response_id),
                        "finding_id": (
                            str(finding_id) if finding_id else None
                        ),
                        "canary_leaked": verdict.leaked,
                        "judge_reason": verdict.reason,
                    })

                except Exception:
                    db.rollback()
                    attempt = db.get(AttackAttempt, attempt_id)
                    attempt.status = "failed"
                    db.commit()
                    logger.exception(
                        "Probe failed: scan=%s attempt=%s",
                        scan_id,
                        attempt_id,
                    )
                    raise

        return {
            "mode": "local_test",
            "scan_id": str(scan_id),
            "attacks_executed": len(results),
            "results": results,
        }