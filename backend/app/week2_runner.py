from uuid import UUID, uuid4

from attack_engine.attack_run import AttackRun

from .attack_engine import AttackEngine
from .attack_persistence import persist_attack_run
from .baseline_review import review_attack
from .database import SessionLocal
from .evaluation_storage import store_evaluation
from .local_target import OLLAMA_BASE_URL
from .models import Target
from .security_review import review_stored_response
from .trusted_local_target import execute_canary_probe


class Week2AttackRunner:
    def run(self, scan_id: UUID, target_id: UUID) -> dict:
        with SessionLocal() as db:
            target = db.get(Target, target_id)
            if target is None:
                raise ValueError("Target not found")
            if target.endpoint.rstrip("/") != OLLAMA_BASE_URL:
                raise ValueError("Only the configured local target is supported")
            endpoint = target.endpoint

        probe = AttackEngine(profile="week1_local").probes()[0]
        if probe.attack_case_id != "SPL-001":
            raise ValueError("Unexpected probe for the local canary test")

        attack = AttackRun(
            attack_id=probe.attack_case_id,
            category=probe.category,
            payload=probe.payload,
            target=endpoint,
            strategy=probe.strategy,
            expected_behavior=probe.expected_behavior,
        )

        try:
            text, canary, fixture = execute_canary_probe(probe.payload)
        except Exception:
            attack.status = "failed"
            with SessionLocal() as db:
                persist_attack_run(db, scan_id=scan_id, attack=attack)
                db.commit()
            raise

        attack.actual_response = text
        attack.status = "completed"
        attack.evaluation_status = "pending"

        with SessionLocal() as db:
            ids = persist_attack_run(db, scan_id=scan_id, attack=attack)
            db.commit()

        baselines = review_attack(attack, canary=canary)
        finding_id = uuid4()

        with SessionLocal() as db:
            security = review_stored_response(
                db,
                attempt_id=ids["attempt_id"],
                response_id=ids["response_id"],
                test_case_id="TC-002",
                trusted_fixture=fixture,
                finding_id=finding_id,
            )
            evaluation = store_evaluation(
                db,
                response_id=ids["response_id"],
                baseline_results=baselines,
                security_result=security,
            )
            evaluation_id = evaluation.id
            db.commit()

        leaked = security["validation"]["verdict"] == "LEAK"
        return {
            "mode": "week2_local",
            "scan_id": str(scan_id),
            "attacks_executed": 1,
            "results": [{
                "attempt_id": str(ids["attempt_id"]),
                "response_id": str(ids["response_id"]),
                "evaluation_id": str(evaluation_id),
                "attack_case_id": probe.attack_case_id,
                "test_case_id": "TC-002",
                "security_verdict": security["validation"]["verdict"],
                "finding_id": str(finding_id) if leaked else None,
            }],
        }