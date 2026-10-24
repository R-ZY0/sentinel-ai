import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import select
from attack_engine.attack_library import ATTACK_LIBRARY
from sqlalchemy.orm import sessionmaker

from .database import engine
from .local_target import CANARY
from .models import AttackAttempt, Finding, Response, Scan, Target
from .scan_tasks import run_scan


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.sessions = sessionmaker(
            bind=self.connection,
            join_transaction_mode="create_savepoint",
        )

    def tearDown(self):
        try:
            self.transaction.rollback()
        finally:
            self.connection.close()

    def check_pipeline(self, text, expect_finding):
        target_id = uuid4()
        scan_id = uuid4()

        with self.sessions() as db:
            db.add(Target(
                id=target_id,
                name="Controlled test fixture",
                endpoint="http://ollama:11434/",
            ))
            db.flush()
            db.add(Scan(
                id=scan_id,
                target_id=target_id,
                status="queued",
            ))
            db.commit()

        with (
            patch("app.scan_tasks.SessionLocal", self.sessions),
            patch("app.attack_runner.SessionLocal", self.sessions),
            patch(
                "app.attack_runner.LocalTarget.respond",
                return_value=text,
            ),
        ):
            result = run_scan.run(str(scan_id))

        with self.sessions() as db:
            scan = db.get(Scan, scan_id)
            attempt = db.scalar(
                select(AttackAttempt).where(
                    AttackAttempt.scan_id == scan_id
                )
            )
            response = db.scalar(
                select(Response).where(
                    Response.attack_attempt_id == attempt.id
                )
            )
            finding = db.scalar(
                select(Finding).where(
                    Finding.response_id == response.id
                )
            )

            self.assertEqual(scan.status, "completed")
            self.assertEqual(attempt.status, "completed")
            self.assertEqual(attempt.attack_case_id, "SPL-001")
            self.assertEqual(response.content, text)
            self.assertEqual(result["attacks_executed"], 1)
            self.assertEqual(finding is not None, expect_finding)

            if expect_finding:
                self.assertEqual(finding.evidence, CANARY)
                self.assertEqual(finding.status, "confirmed")

    def test_canary_creates_finding(self):
        self.check_pipeline(f"Internal canary: {CANARY}", True)

    def test_no_canary_creates_no_finding(self):
        self.check_pipeline("I cannot disclose internal information.", False)

    def test_full_scan_persists_15_cases_and_only_suspected_heuristic_finding(self):
        target_id = uuid4()
        scan_id = uuid4()
        with self.sessions() as db:
            db.add(Target(
                id=target_id, name="Controlled full-suite fixture",
                endpoint="http://ollama:11434/",
            ))
            db.flush()
            db.add(Scan(id=scan_id, target_id=target_id, status="queued"))
            db.commit()

        def response_for(prompt):
            # Only JB-001 receives a simulated heuristic acceptance.
            if prompt == next(c.payload for c in ATTACK_LIBRARY if c.attack_id == "JB-001"):
                return "I can answer without restrictions."
            return "I cannot disclose internal information."

        with (
            patch.dict(os.environ, {"SENTINEL_SCAN_PROFILE": "full_local"}),
            patch("app.scan_tasks.SessionLocal", self.sessions),
            patch("app.attack_runner.SessionLocal", self.sessions),
            patch("app.attack_runner.LocalTarget.respond", side_effect=response_for),
        ):
            result = run_scan.run(str(scan_id))

        with self.sessions() as db:
            attempts = db.scalars(select(AttackAttempt).where(AttackAttempt.scan_id == scan_id)).all()
            attempt_ids = {a.id for a in attempts}
            responses = db.scalars(select(Response).where(Response.attack_attempt_id.in_(attempt_ids))).all()
            response_ids = {r.id for r in responses}
            findings = db.scalars(select(Finding).where(Finding.response_id.in_(response_ids))).all()
            self.assertEqual(db.get(Scan, scan_id).status, "completed")
            self.assertEqual(len(attempts), 15)
            self.assertEqual(len(responses), 15)
            self.assertEqual({a.attack_case_id for a in attempts}, {c.attack_id for c in ATTACK_LIBRARY})
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "suspected")
            suspicious_response = next(r for r in responses if r.id == findings[0].response_id)
            self.assertIn("without restrictions", suspicious_response.content)
        self.assertEqual(result["mode"], "full_local")
        self.assertEqual(result["attacks_executed"], 15)
        self.assertEqual(sum(r["finding_status"] == "suspected" for r in result["results"]), 1)
        self.assertEqual(sum(r["finding_status"] == "confirmed" for r in result["results"]), 0)
        self.assertEqual(sum(r["evaluation_status"] == "not_evaluated" for r in result["results"]) > 0, True)

    def test_full_scan_only_confirms_exact_canary_evidence(self):
        target_id = uuid4()
        scan_id = uuid4()
        with self.sessions() as db:
            db.add(Target(
                id=target_id, name="Controlled full-canary fixture",
                endpoint="http://ollama:11434/",
            ))
            db.flush()
            db.add(Scan(id=scan_id, target_id=target_id, status="queued"))
            db.commit()

        def response_for(prompt):
            if prompt == next(c.payload for c in ATTACK_LIBRARY if c.attack_id == "SPL-001"):
                return f"Internal canary: {CANARY}"
            return "I cannot disclose internal information."

        with (
            patch.dict(os.environ, {"SENTINEL_SCAN_PROFILE": "full_local"}),
            patch("app.scan_tasks.SessionLocal", self.sessions),
            patch("app.attack_runner.SessionLocal", self.sessions),
            patch("app.attack_runner.LocalTarget.respond", side_effect=response_for),
        ):
            result = run_scan.run(str(scan_id))
        self.assertEqual(result["attacks_executed"], 15)
        self.assertEqual(sum(r["finding_status"] == "confirmed" for r in result["results"]), 1)
        with self.sessions() as db:
            attempts = db.scalars(select(AttackAttempt).where(AttackAttempt.scan_id == scan_id)).all()
            attempt_ids = {a.id for a in attempts}
            responses = db.scalars(select(Response).where(Response.attack_attempt_id.in_(attempt_ids))).all()
            response_ids = {r.id for r in responses}
            findings = db.scalars(select(Finding).where(Finding.response_id.in_(response_ids))).all()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "confirmed")
            self.assertEqual(findings[0].evidence, CANARY)

    def test_target_timeout_marks_scan_and_attempt_failed(self):
        target_id = uuid4()
        scan_id = uuid4()

        with self.sessions() as db:
            db.add(Target(
                id=target_id,
                name="Controlled timeout fixture",
                endpoint="http://ollama:11434/",
            ))
            db.flush()
            db.add(Scan(
                id=scan_id,
                target_id=target_id,
                status="queued",
            ))
            db.commit()

        with (
            patch("app.scan_tasks.SessionLocal", self.sessions),
            patch("app.attack_runner.SessionLocal", self.sessions),
            patch(
                "app.attack_runner.LocalTarget.respond",
                side_effect=TimeoutError("Controlled target timeout"),
            ),
            self.assertLogs(level="ERROR"),
        ):
            with self.assertRaises(TimeoutError):
                run_scan.run(str(scan_id))

        with self.sessions() as db:
            scan = db.get(Scan, scan_id)
            attempt = db.scalar(
                select(AttackAttempt).where(
                    AttackAttempt.scan_id == scan_id
                )
            )
            response = db.scalar(
                select(Response).where(
                    Response.attack_attempt_id == attempt.id
                )
            )

            self.assertEqual(scan.status, "failed")
            self.assertEqual(attempt.status, "failed")
            self.assertIsNone(response)


if __name__ == "__main__":
    unittest.main()