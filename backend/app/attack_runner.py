"""Week-01 local scan runner, using Cyber Attack Library + AI Canary Judge.

The Backend owns persistence. Exactly one approved local probe is used for P0.
"""
import logging
from uuid import UUID

from attack_engine.attack_run import AttackRun
from judge.canary_judge import CanaryRegexJudge
from judge.verdict import Verdict

from .attack_engine import AttackEngine
from .attack_persistence import persist_attack_run
from .database import SessionLocal
from .local_target import LocalTarget, OLLAMA_BASE_URL, CANARY
from .models import Target

logger = logging.getLogger(__name__)


class AttackRunner:
    def run(self, scan_id: UUID, target_id: UUID) -> dict:
        with SessionLocal() as db:
            target = db.get(Target, target_id)
            if target is None:
                raise ValueError("Target not found")
            if target.endpoint.rstrip("/") != OLLAMA_BASE_URL:
                raise ValueError(
                    "Week-01 runner supports only the configured local Ollama target"
                )
            target_endpoint = target.endpoint

        results = []
        detector = CanaryRegexJudge(canaries=[CANARY])
        for probe in AttackEngine().probes():
            attack = AttackRun(
                attack_id=probe.attack_case_id,
                category=probe.category,
                payload=probe.payload,
                target=target_endpoint,
                strategy=probe.strategy,
                expected_behavior=probe.expected_behavior,
                status="pending",
            )
            try:
                response_text = LocalTarget().respond(probe.payload)
                if not isinstance(response_text, str) or not response_text.strip():
                    raise ValueError("Local target returned an empty response")

                verdict = detector.judge(response_text)
                leaked = verdict.verdict == Verdict.LEAK
                attack.actual_response = response_text
                attack.status = "completed"

                with SessionLocal() as db:
                    ids = persist_attack_run(
                        db,
                        scan_id=scan_id,
                        attack=attack,
                        finding_evidence=CANARY if leaked else None,
                        confirmed=leaked,  # Exact planted local test canary.
                    )
                    db.commit()

                logger.info(
                    "Week-01 probe completed: scan=%s case=%s leaked=%s",
                    scan_id, probe.attack_case_id, leaked,
                )
                results.append({
                    "attempt_id": str(ids["attempt_id"]),
                    "response_id": str(ids["response_id"]),
                    "finding_id": (
                        str(ids["finding_id"])
                        if ids["finding_id"] is not None else None
                    ),
                    "attack_case_id": ids["attack_case_id"],
                    "canary_leaked": leaked,
                    "judge_reason": verdict.reason,
                })
            except Exception:
                logger.exception(
                    "Week-01 probe failed: scan=%s case=%s",
                    scan_id, probe.attack_case_id,
                )
                # Preserve a failed attempt when target/judge execution failed.
                # A DB-write failure should bubble up, not create a fake result.
                if attack.status != "completed":
                    attack.status = "failed"
                    attack.actual_response = None
                    with SessionLocal() as db:
                        persist_attack_run(db, scan_id=scan_id, attack=attack)
                        db.commit()
                raise

        return {
            "mode": "week1_local",
            "scan_id": str(scan_id),
            "attacks_executed": len(results),
            "results": results,
        }
