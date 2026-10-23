"""SQLite contract smoke test; PostgreSQL/Docker E2E is a separate gate."""
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Target, Scan, AttackAttempt, Response, Finding
from app.attack_persistence import persist_attack_run
from attack_engine.attack_run import AttackRun


class TestFindingDatabaseIntegration(unittest.TestCase):
    def test_full_attack_response_finding_chain(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            target = Target(name="fixture", endpoint="http://ollama:11434/")
            db.add(target)
            db.flush()
            scan = Scan(target_id=target.id, status="running")
            db.add(scan)
            db.flush()
            attack = AttackRun(
                attack_id="PI-001", category="Prompt Injection",
                payload="Authorized fixture", target="local",
                strategy="test", expected_behavior="refuse",
                actual_response="PWNED", status="completed"
            )
            ids = persist_attack_run(
                db, scan_id=scan.id, attack=attack, finding_evidence="PWNED"
            )
            db.commit()
            self.assertEqual(
                db.get(AttackAttempt, ids["attempt_id"]).attack_case_id,
                "PI-001"
            )
            self.assertEqual(
                db.get(Response, ids["response_id"]).attack_attempt_id,
                ids["attempt_id"]
            )
            self.assertEqual(
                db.get(Finding, ids["finding_id"]).status, "suspected"
            )
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
