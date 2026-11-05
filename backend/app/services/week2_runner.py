import logging
import os
from uuid import UUID, uuid4

from attack_engine.attack_run import AttackRun

from .attack_engine import AttackEngine
from .attack_persistence import persist_attack_run
from .baseline_review import review_attack
from ..database import SessionLocal
from .evaluation_storage import store_evaluation
from ..local_target import OLLAMA_BASE_URL
from ..models import Target, Scan
from .scan_control import cancellation_checkpoint, lock_scan_for_write
from .target_adapters import require_scan_compatible
from .security_review import review_stored_response
from .trusted_local_target import execute_canary_probe
from ..tools.client import execute_tool_attacks

logger = logging.getLogger(__name__)


class Week2AttackRunner:
    def run(self, scan_id: UUID, target_id: UUID) -> dict:
        with SessionLocal() as db:
            target = db.get(Target, target_id)
            if target is None:
                raise ValueError("Target not found")
            require_scan_compatible(target)
            if target.endpoint.rstrip("/") != OLLAMA_BASE_URL:
                raise ValueError("Only the configured local target is supported")
            endpoint = target.endpoint
            scan = db.get(Scan, scan_id)
            configuration = scan.configuration if scan else None
            configured_engines = list(configuration.engines) if configuration else None
            selections = [dict(item.definition) for item in sorted(configuration.selections, key=lambda item: item.position)] if configuration else []
            if configuration and configuration.target_snapshot != {
                "endpoint": target.endpoint, "target_type": target.target_type,
                "configuration": target.configuration or {}, "authorized": target.authorized,
            }:
                raise ValueError("Target no longer matches the scan configuration")

        sources = os.environ.get("WEEK2_ATTACK_ENGINES", "library").split(",")
        sources = [source.strip() for source in sources]
        if configured_engines:
            sources = configured_engines
        if (not sources or len(sources) != len(set(sources))
                or any(source not in {"library", "pyrit", "garak"} for source in sources)):
            raise ValueError("WEEK2_ATTACK_ENGINES must list unique supported engines")

        results = []
        for source in sources:
            cancellation_checkpoint(SessionLocal, scan_id)
            logger.info("Week 2 execution started: scan=%s engine=%s", scan_id, source)
            if source == "library":
                chosen = [item for item in selections if item["engine"] == "library"] or [None]
                executions = []
                for definition in chosen:
                    cancellation_checkpoint(SessionLocal, scan_id)
                    attack, canary, fixture = self._execute_library(scan_id, endpoint, definition)
                    executions.append((attack, canary, fixture, None))
            else:
                attacks, canary, fixture = execute_tool_attacks(source)
                executions = [(item.attack, canary, fixture, item.source_attempt_id) for item in attacks]
            for attack, canary, fixture, source_id in executions:
                cancellation_checkpoint(SessionLocal, scan_id)
                results.append(self._evaluate(
                    scan_id, attack, canary, fixture, source, source_id
                ))
        return {
            "mode": "week2_local", "scan_id": str(scan_id),
            "attacks_executed": len(results), "results": results,
        }

    def _execute_library(self, scan_id, endpoint, definition=None):
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
        if definition:
            attack.attack_id = definition["id"]
            attack.category = definition["category"]
            attack.payload = definition["payload"]
            attack.strategy = definition["strategy"]
            attack.expected_behavior = definition["expected_behavior"]

        try:
            text, canary, fixture = execute_canary_probe(attack.payload)
        except Exception:
            attack.status = "failed"
            with SessionLocal() as db:
                lock_scan_for_write(db, scan_id)
                persist_attack_run(db, scan_id=scan_id, attack=attack)
                db.commit()
            raise

        attack.actual_response = text
        attack.status = "completed"
        attack.evaluation_status = "pending"
        return attack, canary, fixture

    def _evaluate(self, scan_id, attack, canary, fixture, source, source_id=None):
        cancellation_checkpoint(SessionLocal, scan_id)
        with SessionLocal() as db:
            lock_scan_for_write(db, scan_id)
            ids = persist_attack_run(db, scan_id=scan_id, attack=attack)
            catalog_id = "PYRIT-PI-001" if source == "pyrit" else attack.attack_id
            from ..models import Attack, AttackAttempt
            if db.get(Attack, catalog_id) is not None:
                db.get(AttackAttempt, ids["attempt_id"]).attack_id = catalog_id
            db.commit()

        logger.info("Week 2 judging started: scan=%s engine=%s", scan_id, source)
        baselines = review_attack(attack, canary=canary)
        baselines = {
            **baselines,
            "execution": {
                "engine": source, "strategy": attack.strategy,
                "source_attempt_id": source_id,
            },
        }
        finding_id = uuid4()
        cancellation_checkpoint(SessionLocal, scan_id)

        with SessionLocal() as db:
            lock_scan_for_write(db, scan_id)
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
        logger.info(
            "Week 2 evaluation stored: scan=%s engine=%s verdict=%s",
            scan_id, source, security["validation"]["verdict"],
        )
        return {
            "engine": source,
            "attempt_id": str(ids["attempt_id"]),
            "response_id": str(ids["response_id"]),
            "evaluation_id": str(evaluation_id),
            "attack_case_id": attack.attack_id,
            "source_attempt_id": source_id,
            "test_case_id": "TC-002",
            "security_verdict": security["validation"]["verdict"],
            "finding_id": str(finding_id) if leaked else None,
        }

