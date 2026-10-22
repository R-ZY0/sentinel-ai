import unittest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, select, event
from sqlalchemy.orm import sessionmaker

from .database import Base
from .local_target import CANARY
from .models import AttackAttempt, Finding, Response, Scan, Target
from .scan_tasks import run_scan


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

        @event.listens_for(self.engine, "connect")
        def enable_foreign_keys(dbapi_connection, connection_record):
            dbapi_connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.connection = self.engine.connect()
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
            self.engine.dispose()

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
            patch("backend.app.scan_tasks.SessionLocal", self.sessions),
            patch("backend.app.attack_runner.SessionLocal", self.sessions),
            patch(
                "backend.app.attack_runner.LocalTarget.respond",
                return_value=text,
            ),
        ):
            result = run_scan.run(str(scan_id))

        with self.sessions() as db:
            scan = db.get(Scan, scan_id)
            attempts = db.scalars(
                select(AttackAttempt).where(
                    AttackAttempt.scan_id == scan_id
                )
            ).all()

            self.assertEqual(scan.status, "completed")
            self.assertEqual(len(attempts), 15)
            self.assertEqual(result["attacks_executed"], 15)
            self.assertEqual(len(result["results"]), 15)

            for attempt in attempts:
                self.assertEqual(attempt.status, "completed")

                responses = db.scalars(
                    select(Response).where(
                        Response.attack_attempt_id == attempt.id
                    )
                ).all()

                self.assertEqual(len(responses), 1)
                response = responses[0]
                self.assertEqual(response.content, text)

                findings = db.scalars(
                    select(Finding).where(
                        Finding.response_id == response.id
                    )
                ).all()

                self.assertEqual(
                    len(findings),
                    1 if expect_finding else 0
                )

                if expect_finding:
                    self.assertEqual(findings[0].evidence, CANARY)
                    self.assertEqual(findings[0].status, "confirmed")

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