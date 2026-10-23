import unittest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import select
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