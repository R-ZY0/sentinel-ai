"""Combined team pipeline: selected AttackDefinition -> real target -> LLM -> evidence -> DB."""
import logging
import time
from datetime import datetime, timezone
from uuid import uuid4
from attack_engine.attack_runner import AttackRunner
from attack_engine.attack_run import AttackRun
from attack_engine.attack_schema import AttackDefinition
from attack_engine.normalized_attack_adapter import normalized_attack_to_attack_run
from ..database import SessionLocal
from ..models import Scan, Target, AttackAttempt, Response
from ..tools.client import execute_tool_attacks
from .target_adapters import require_scan_compatible
from .scan_control import cancellation_checkpoint, lock_scan_for_write
from .week34_scenarios import ScenarioTarget, CASE_BY_ATTACK, redact
from .attack_persistence import persist_attack_run
from .evaluation_storage import store_evaluation
from .receipts import audit_key, attest
from .week34_review import review

logger = logging.getLogger(__name__)


class Week34AttackRunner:
    def run(self, scan_id, target_id):
        audit_key()  # Fail before any target call if persistent signing is unavailable.
        with SessionLocal() as db:
            target = db.get(Target, target_id)
            if target is None:
                raise ValueError("Target not found")
            require_scan_compatible(target)
            scan = db.get(Scan, scan_id)
            config = scan.configuration
            if config is None or config.pipeline != "week34":
                raise ValueError("Week 3-4 requires an explicit saved scan configuration")
            snapshot = {"endpoint": target.endpoint, "target_type": target.target_type,
                        "configuration": target.configuration or {}, "authorized": target.authorized}
            if config.target_snapshot != snapshot:
                raise ValueError("Target changed after scan configuration")
            selections = [dict(item.definition) for item in sorted(config.selections, key=lambda item: item.position)]
            db.expunge(target)
        results = []
        for selected in selections:
            cancellation_checkpoint(SessionLocal, scan_id)
            case_id = CASE_BY_ATTACK.get(selected["id"])
            if case_id is None or selected.get("test_case_id") != case_id:
                raise ValueError("Attack lacks a trusted scenario mapping")
            source = selected["engine"]
            logger.info("Week 3-4 execution started: scan=%s engine=%s case=%s", scan_id, source, case_id)
            if source == "library":
                normalized = dict(selected["normalized_definition"])
                # The frozen DB snapshot is authoritative, not target output.
                normalized.update(category=selected["category"], payload=selected["payload"],
                    strategy=selected["strategy"], expected_behavior=selected["expected_behavior"])
                definition = AttackDefinition(**normalized)
                if definition.attack_id != selected["id"]:
                    raise ValueError("Normalized attack identity mismatch")
                adapter = ScenarioTarget(target, case_id)
                attack = normalized_attack_to_attack_run(definition, target.endpoint)
                started = datetime.now(timezone.utc).isoformat()
                clock = time.monotonic()
                attack = AttackRunner(adapter.respond, timeout_seconds=target.configuration.get("timeout_seconds", 30) + 2,
                    max_retries=0).run(attack)
                elapsed = round((time.monotonic() - clock) * 1000)
                records = [(attack, adapter.fixture, None, {"started_at": started,
                    "finished_at": datetime.now(timezone.utc).isoformat(), "latency_ms": elapsed,
                    "latency_scope": "individual-target-call", "trajectory": adapter.trajectory})]
            elif source in {"pyrit", "garak"}:
                clock = time.monotonic()
                started = datetime.now(timezone.utc).isoformat()
                try:
                    attacks, _, fixture = execute_tool_attacks(source)
                except Exception:
                    failed = AttackRun(attack_id=selected["id"], category=selected["category"],
                        payload=selected["payload"], target=target.endpoint, strategy=selected["strategy"],
                        expected_behavior=selected["expected_behavior"], status="failed",
                        execution_error="ScannerServiceError", evaluation_status="not_evaluated")
                    self._store(scan_id, target_id, selected, case_id, failed,
                        {"values": []}, {"started_at": started,
                            "finished_at": datetime.now(timezone.utc).isoformat(),
                            "latency_ms": round((time.monotonic() - clock) * 1000),
                            "latency_scope": "scanner-service-batch", "error": "scanner_service_failed"}, None)
                    raise
                elapsed = round((time.monotonic() - clock) * 1000)
                records = [(item.attack, fixture, item.source_attempt_id, {"started_at": started,
                    "finished_at": datetime.now(timezone.utc).isoformat(), "latency_ms": elapsed,
                    "tool_version": item.tool_version,
                    "latency_scope": "scanner-service-batch", "trajectory": {"mode": "protected",
                        "source_attempt_id": item.source_attempt_id}}) for item in attacks]
            else:
                raise ValueError("Unsupported scan engine")
            for attack, fixture, source_id, metadata in records:
                results.append(self._store(scan_id, target_id, selected, case_id, attack, fixture, metadata, source_id))
        return {"mode": "week34_local", "scan_id": str(scan_id), "attacks_executed": len(results), "results": results}

    def _store(self, scan_id, target_id, selected, case_id, attack, fixture, metadata, source_id):
        cancellation_checkpoint(SessionLocal, scan_id)
        failed = attack.status != "completed" or bool(attack.execution_error)
        execution = {**metadata, "scan_id": str(scan_id), "target_id": str(target_id),
            "attack_id": attack.attack_id, "test_case_id": case_id, "engine": selected["engine"],
            "status": attack.status, "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": metadata.get("error", "target_execution_failed") if failed else None,
            "redacted_response": redact(attack.actual_response, fixture["values"])}
        with SessionLocal() as db:
            lock_scan_for_write(db, scan_id)
            ids = persist_attack_run(db, scan_id=scan_id, attack=attack)
            attempt = db.get(AttackAttempt, ids["attempt_id"])
            attempt.attack_id = selected["id"]
            attempt.test_case_id = case_id
            attempt.execution_metadata = execution
            db.commit()
        if failed:
            raise RuntimeError("Target execution failed; structured attempt retained")
        logger.info("Week 3-4 judging started: scan=%s case=%s", scan_id, case_id)
        comparison = review(attack, fixture)
        cancellation_checkpoint(SessionLocal, scan_id)
        with SessionLocal() as db:
            lock_scan_for_write(db, scan_id)
            attempt = db.get(AttackAttempt, ids["attempt_id"])
            response = db.get(Response, ids["response_id"])
            security = attest(db, attempt=attempt, response=response, fixture=fixture, finding_id=uuid4())
            # JudgeVerdict remains advisory; only independent validation can confirm a finding.
            comparison = {**comparison, "execution": {"engine": selected["engine"], "source_attempt_id": source_id}}
            evaluation = store_evaluation(db, response_id=response.id,
                baseline_results=comparison, security_result=security)
            evaluation_id = str(evaluation.id)
            db.commit()
        logger.info("Week 3-4 evaluation stored: scan=%s case=%s verdict=%s", scan_id, case_id, security["validation"]["verdict"])
        return {"engine": selected["engine"], "attack_case_id": attack.attack_id,
            "test_case_id": case_id, "attempt_id": str(ids["attempt_id"]),
            "response_id": str(ids["response_id"]), "evaluation_id": evaluation_id,
            "judge_verdict": comparison["llm_judge"]["verdict"],
            "security_verdict": security["validation"]["verdict"],
            "finding_id": security["finding"]["finding_id"] if security["validation"]["verdict"] == "LEAK" else None}
