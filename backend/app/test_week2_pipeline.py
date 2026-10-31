import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from .database import engine
from .evaluation_storage import store_evaluation
from .models import (
    AttackAttempt,
    Finding,
    Response,
    ResponseEvaluation,
    Scan,
    Target,
)
from .scan_tasks import run_scan


class Week2PipelineTests(unittest.TestCase):
    def setUp(self):
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.sessions = sessionmaker(
            bind=self.connection,
            join_transaction_mode="create_savepoint",
        )
        self.scan_id = uuid4()
        self.canary = "SYNTHETIC_TEST_" + uuid4().hex

        with self.sessions() as db:
            target = Target(
                id=uuid4(),
                name="Week 2 controlled test",
                endpoint="http://ollama:11434/",
            )
            db.add(target)
            db.flush()
            db.add(Scan(
                id=self.scan_id,
                target_id=target.id,
                status="queued",
            ))
            db.commit()

    def tearDown(self):
        try:
            self.transaction.rollback()
        finally:
            self.connection.close()

    def execute(self, text, *, verified=True, judge_error=None):
        fixture = {
            "test_case_id": "TC-002",
            "target_authorized": True,
            "requester_authorized": False,
            "source_verified": verified,
            "fixture_loaded": True,
            "values": [{
                "id": "controlled-test-canary",
                "kind": "canary",
                "value": self.canary,
            }],
        }
        baseline_result = {
            "attack_id": "SPL-001",
            "advisory_only": True,
            "baselines": {
                name: {
                    "verdict": "NO_LEAK",
                    "confidence": 0.5,
                    "reason": "Controlled judge fixture",
                    "signals": {},
                }
                for name in ("B0", "B1", "B2", "B3")
            },
        }

        with (
            patch.dict(os.environ, {"SENTINEL_PIPELINE": "week2"}),
            patch("app.scan_tasks.SessionLocal", self.sessions),
            patch("app.week2_runner.SessionLocal", self.sessions),
            patch(
                "app.week2_runner.execute_canary_probe",
                return_value=(text, self.canary, fixture),
            ),
            patch(
                "app.week2_runner.review_attack",
                return_value=baseline_result,
                side_effect=judge_error,
            ),
        ):
            return run_scan.run(str(self.scan_id))

    def stored_records(self, db):
        attempt = db.scalar(
            select(AttackAttempt).where(
                AttackAttempt.scan_id == self.scan_id
            )
        )
        response = db.scalar(
            select(Response).where(
                Response.attack_attempt_id == attempt.id
            )
        )
        evaluation = db.scalar(
            select(ResponseEvaluation).where(
                ResponseEvaluation.response_id == response.id
            )
        )
        findings = db.scalars(
            select(Finding).where(Finding.response_id == response.id)
        ).all()
        return response, evaluation, findings

    def test_verified_leak_creates_redacted_finding(self):
        result = self.execute(f"The internal value is {self.canary}")

        with self.sessions() as db:
            response, evaluation, findings = self.stored_records(db)
            self.assertEqual(db.get(Scan, self.scan_id).status, "completed")
            self.assertEqual(result["mode"], "week2_local")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "confirmed")
            self.assertNotIn(self.canary, findings[0].evidence)
            document = evaluation.security_result["finding"]
            self.assertEqual(document["finding_id"], str(findings[0].id))
            self.assertEqual(document["status"], "confirmed")
            self.assertIn("classification", document)
            self.assertEqual(
                set(evaluation.baseline_results["baselines"]),
                {"B0", "B1", "B2", "B3"},
            )

            repeated = store_evaluation(
                db,
                response_id=response.id,
                baseline_results=evaluation.baseline_results,
                security_result=evaluation.security_result,
            )
            self.assertEqual(repeated.id, evaluation.id)
            self.assertEqual(
                len(db.scalars(
                    select(Finding).where(
                        Finding.response_id == response.id
                    )
                ).all()),
                1,
            )

    def test_safe_response_stores_evaluation_without_finding(self):
        self.execute("I cannot disclose internal information.")

        with self.sessions() as db:
            _, evaluation, findings = self.stored_records(db)
            self.assertEqual(findings, [])
            self.assertEqual(
                evaluation.security_result["validation"]["verdict"],
                "NO_LEAK",
            )

    def test_unverified_fixture_cannot_create_confirmed_finding(self):
        self.execute(self.canary, verified=False)

        with self.sessions() as db:
            _, evaluation, findings = self.stored_records(db)
            self.assertEqual(findings, [])
            self.assertEqual(
                evaluation.security_result["validation"]["verdict"],
                "AMBIGUOUS",
            )

    def test_judge_failure_preserves_response_and_fails_scan(self):
        with self.assertLogs(level="ERROR"):
            with self.assertRaises(TimeoutError):
                self.execute(
                    "Controlled target response",
                    judge_error=TimeoutError("Controlled judge timeout"),
                )

        with self.sessions() as db:
            response, evaluation, findings = self.stored_records(db)
            self.assertEqual(db.get(Scan, self.scan_id).status, "failed")
            self.assertEqual(response.content, "Controlled target response")
            self.assertIsNone(evaluation)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()