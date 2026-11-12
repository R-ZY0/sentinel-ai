"""Full five-case orchestration with controlled network/LLM transport only.

The actual normalized runner, Week3LLMJudge, evidence rules, receipt creation,
API configuration, and DB persistence run here. Live acceptance is separate.
"""
import copy
import json
import os
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock
from uuid import UUID
from sqlalchemy import select, func

from . import test_targets_and_scans as support
from ..models import AttackAttempt, Response, ResponseEvaluation, EvidenceReceipt, Finding, Scan
from ..tasks.scans import run_scan
from ..services.target_adapters import TargetReply
from ..services.receipts import stored_receipt_integrity
from judge.week3_llm_judge import Week3LLMJudge
from judge.verdict import JudgeVerdict, Verdict

ATTACKS = ["SPL-001", "DL-001", "RL-001", "DL-003", "PI-002"]
VALUE = re.compile(r"(?:INTERNAL_SYNTHETIC_RULE_|SENTINEL_EPHEMERAL_|SYNTHETIC_RESTRICTED_DOCUMENT_)[0-9a-f]{48}|synthetic-[0-9a-f]{48}@example\.test")


class Week34IntegrationTests(unittest.TestCase):
    setUpDatabase = support.TargetAndScanTests.setUp
    tearDownDatabase = support.TargetAndScanTests.tearDown
    target = support.TargetAndScanTests.target
    scan = support.TargetAndScanTests.scan

    def setUp(self):
        self.setUpDatabase()
        self.environment = patch.dict(os.environ, {"EVIDENCE_AUDIT_KEY": "12" * 32, "WEEK34_TARGET_MODE": "protected"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.tearDownDatabase()

    def execute(self, *, leak=False, failed=False, judge_error=False, attacks=None, engines=None, tool_results=None):
        scan = self.scan(configuration={"pipeline": "week34", "engines": engines or ["library"], "attack_ids": attacks or ATTACKS})
        with patch("app.routers.scans.run_scan.apply_async"):
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/start").status_code, 202)
        client = Mock()
        client.chat.return_value = SimpleNamespace(message=SimpleNamespace(content=json.dumps({
            "verdict": "NO_LEAK", "confidence": 0.8, "reason": "Controlled model assessment", "signals": {}})))
        if judge_error:
            client.chat.side_effect = TimeoutError("Controlled model timeout")
        llm = Week3LLMJudge(client=client)
        pii = Mock()
        pii.judge.return_value = JudgeVerdict(Verdict.NO_LEAK, 0.8, "Controlled PII detector")
        protected_values = []

        def target_reply(adapter, body, url, field):
            self.assertEqual(url, "http://ollama:11434/api/chat")
            value = VALUE.search(body["messages"][0]["content"]).group()
            protected_values.append(value)
            self.assertNotIn(value, body["messages"][1]["content"])
            if failed:
                raise TimeoutError("Controlled target timeout")
            return TargetReply(value if leak else "I cannot disclose protected information.", "completed", 7)

        with patch("app.tasks.scans.SessionLocal", self.sessions), \
             patch("app.services.week34_runner.SessionLocal", self.sessions), \
             patch("app.services.target_adapters.TargetAdapter._post", autospec=True, side_effect=target_reply), \
             patch("app.services.week34_review.judges", return_value=(pii, llm)), \
             patch("app.services.week34_runner.execute_tool_attacks", side_effect=tool_results), \
             patch("app.services.week34_review.runtime_metadata", return_value={"judge_model": "llama3.2:3b", "seed": 42}):
            if failed:
                with self.assertLogs("app.tasks.scans", level="ERROR"), self.assertRaises(RuntimeError):
                    run_scan.run(scan["id"])
                result = None
            else:
                result = run_scan.run(scan["id"])
        return scan, result, protected_values, client

    def test_five_real_component_paths_store_confirmed_findings_and_verified_receipts(self):
        scan, result, values, llm = self.execute(leak=True)
        self.assertEqual(result["attacks_executed"], 5)
        self.assertEqual({item["test_case_id"] for item in result["results"]}, {f"TC-{n:03}" for n in range(1, 6)})
        self.assertTrue(all(item["security_verdict"] == "LEAK" and item["judge_verdict"] == "LEAK" for item in result["results"]))
        self.assertEqual(llm.chat.call_count, 5)
        with self.sessions() as db:
            attempts = db.scalars(select(AttackAttempt).where(AttackAttempt.scan_id == UUID(scan["id"]))).all()
            for attempt in attempts:
                response = attempt.responses[0]
                evaluation = db.scalar(select(ResponseEvaluation).where(ResponseEvaluation.response_id == response.id))
                receipt = db.scalar(select(EvidenceReceipt).where(EvidenceReceipt.response_id == response.id))
                self.assertEqual(stored_receipt_integrity(receipt, attempt, response, evaluation.security_result), "verified")
                self.assertEqual(attempt.execution_metadata["target_id"], scan["target_id"])
                self.assertEqual(len(response.findings), 1)
                self.assertTrue(response.findings[0].evidence_records)
                self.assertEqual({m.taxonomy for m in response.findings[0].mappings}, {"owasp", "cwe"})
                self.assertIsNotNone(attempt.execution_metadata["latency_ms"])
        visible = self.client.get(f"/scans/{scan['id']}/results").text
        self.assertTrue(all(value not in visible for value in values))
        self.assertTrue(all(item["receipt_integrity"] == "verified" for item in self.client.get(f"/scans/{scan['id']}/results").json()["results"]))
        raw = self.client.get(f"/scans/{scan['id']}/results?include_raw=true").text
        self.assertTrue(all(value in raw for value in values))
        self.current_user = self.other
        self.assertEqual(self.client.get(f"/scans/{scan['id']}/results?include_raw=true").status_code, 404)

    def test_five_safe_responses_store_rejected_outcomes_without_confirmed_findings(self):
        scan, result, _, _ = self.execute()
        self.assertTrue(all(item["security_verdict"] == "NO_LEAK" and item["finding_id"] is None for item in result["results"]))
        for item in self.client.get(f"/scans/{scan['id']}/results").json()["results"]:
            self.assertEqual(item["security"]["finding"]["status"], "rejected")
            self.assertEqual(item["receipt_integrity"], "verified")

    def test_failed_target_retains_structured_attempt_without_fabricated_response(self):
        scan, _, _, _ = self.execute(failed=True, attacks=["SPL-001"])
        with self.sessions() as db:
            attempt = db.scalar(select(AttackAttempt).where(AttackAttempt.scan_id == UUID(scan["id"])))
            self.assertEqual(attempt.status, "failed")
            self.assertEqual(attempt.execution_metadata["error"], "target_execution_failed")
            self.assertEqual(attempt.responses, [])
            self.assertEqual(db.get(Scan, UUID(scan["id"])).status, "failed")

    def test_judge_timeout_is_ambiguous_not_a_successful_safety_assessment(self):
        scan, result, _, _ = self.execute(judge_error=True, attacks=["DL-001"])
        self.assertEqual(result["results"][0]["judge_verdict"], "AMBIGUOUS")
        item = self.client.get(f"/scans/{scan['id']}/results").json()["results"][0]
        self.assertEqual(item["comparison"]["llm_judge"]["signals"]["evaluation_error"], "TimeoutError")
        self.assertIsNone(result["results"][0]["finding_id"])

    def test_receipt_tampering_and_response_tampering_are_detected(self):
        scan, _, _, _ = self.execute(attacks=["DL-001"])
        with self.sessions() as db:
            attempt = db.scalar(select(AttackAttempt).where(AttackAttempt.scan_id == UUID(scan["id"])))
            response = attempt.responses[0]
            receipt = db.scalar(select(EvidenceReceipt).where(EvidenceReceipt.response_id == response.id))
            evaluation = db.scalar(select(ResponseEvaluation).where(ResponseEvaluation.response_id == response.id))
            original = copy.deepcopy(receipt.receipt)
            receipt.receipt = {**original, "verdict": "LEAK"}
            self.assertEqual(stored_receipt_integrity(receipt, attempt, response, evaluation.security_result), "invalid")
            receipt.receipt = original
            response.content = "Tampered response"
            self.assertEqual(stored_receipt_integrity(receipt, attempt, response, evaluation.security_result), "invalid")

    def test_missing_signing_key_rejects_start_before_execution(self):
        scan = self.scan(configuration={"pipeline": "week34", "engines": ["library"]})
        with patch.dict(os.environ, {"EVIDENCE_AUDIT_KEY": ""}), patch("app.routers.scans.run_scan.apply_async") as queue:
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/start").status_code, 503)
            queue.assert_not_called()

    def test_scanner_failure_retains_structured_attempt(self):
        scan = self.scan(configuration={"pipeline": "week34", "engines": ["garak"]})
        with patch("app.routers.scans.run_scan.apply_async"):
            self.client.post(f"/scans/{scan['id']}/start")
        with patch("app.tasks.scans.SessionLocal", self.sessions), \
             patch("app.services.week34_runner.SessionLocal", self.sessions), \
             patch("app.services.week34_runner.execute_tool_attacks", side_effect=TimeoutError()), \
             self.assertLogs("app.tasks.scans", level="ERROR"), self.assertRaises(RuntimeError):
            run_scan.run(scan["id"])
        row = self.client.get(f"/scans/{scan['id']}/results").json()["results"][0]
        self.assertEqual(row["execution"]["error"], "scanner_service_failed")
        self.assertIsNone(row["target_response"])
        self.assertIsNone(row["security"])

    def test_both_tool_boundaries_reach_new_judge_and_signed_storage(self):
        from attack_engine.attack_run import AttackRun
        from ..tools.client import ExecutedToolAttack

        def tool_results(tool):
            value = "SYNTHETIC_TOOL_REFERENCE_" + tool + "_123456789"
            attack = AttackRun(attack_id="PI-001" if tool == "pyrit" else "GARAK-DAN-001",
                category="Prompt Injection", payload="Actual tool prompt", target="http://ollama:11434",
                strategy=tool, expected_behavior="Protect the planted reference",
                actual_response=value, status="completed")
            fixture = {"test_case_id": "TC-002", "target_authorized": True, "requester_authorized": False,
                "source_verified": True, "fixture_loaded": True,
                "values": [{"id": "tool-reference", "kind": "canary", "value": value}]}
            return [ExecutedToolAttack(attack, "report-attempt" if tool == "garak" else None, "controlled-version")], value, fixture

        scan, result, _, judge = self.execute(attacks=["PYRIT-PI-001", "GARAK-DAN-001"],
            engines=["pyrit", "garak"], tool_results=tool_results)
        self.assertEqual(result["attacks_executed"], 2)
        self.assertEqual(judge.chat.call_count, 2)
        for row in self.client.get(f"/scans/{scan['id']}/results").json()["results"]:
            self.assertEqual(row["test_case_id"], "TC-002")
            self.assertEqual(row["receipt_integrity"], "verified")
            self.assertEqual(row["execution"]["tool_version"], "controlled-version")

    def test_cancellation_during_new_judging_commits_no_receipt_or_finding(self):
        from ..services import week34_review
        original = week34_review.review

        def cancel_during_review(attack, fixture):
            with self.sessions() as db:
                attempt = db.scalar(select(AttackAttempt).where(AttackAttempt.attack_case_id == attack.attack_id,
                    AttackAttempt.test_case_id == fixture["test_case_id"]).order_by(AttackAttempt.created_at.desc()))
                scan_id = str(attempt.scan_id)
            result = original(attack, fixture)
            self.client.post(f"/scans/{scan_id}/cancel")
            return result

        with patch("app.services.week34_runner.review", side_effect=cancel_during_review):
            scan, _, _, _ = self.execute(attacks=["DL-001"])
        with self.sessions() as db:
            self.assertEqual(db.get(Scan, UUID(scan["id"])).status, "cancelled")
            attempt = db.scalar(select(AttackAttempt).where(AttackAttempt.scan_id == UUID(scan["id"])))
            self.assertIsNone(db.scalar(select(EvidenceReceipt).where(EvidenceReceipt.response_id == attempt.responses[0].id)))


if __name__ == "__main__":
    unittest.main()
