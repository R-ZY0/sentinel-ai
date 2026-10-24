"""Regression: the component's FindingRepository writes real backend fields."""
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Target, Scan, AttackAttempt, Response, Finding
from attack_engine.finding import Finding as DomainFinding
from attack_engine.finding_repository import FindingRepository


class TestFindingRepository(unittest.TestCase):
    def test_saves_suspected_finding_with_real_backend_columns(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            target = Target(name="test", endpoint="http://ollama:11434/")
            db.add(target)
            db.flush()
            scan = Scan(target_id=target.id, status="running")
            db.add(scan)
            db.flush()
            attempt = AttackAttempt(
                scan_id=scan.id, attack_case_id="PI-001",
                category="prompt_injection", payload="test", status="completed"
            )
            db.add(attempt)
            db.flush()
            response = Response(attack_attempt_id=attempt.id, content="PWNED")
            db.add(response)
            db.flush()
            finding = DomainFinding(
                "local-1", "PI-001", "Prompt Injection", "Test",
                "Medium", "Potential issue", evidence="PWNED"
            )
            saved = FindingRepository(db, response_id=response.id).save(finding)
            db.commit()
            self.assertEqual(db.get(Finding, saved.id).status, "suspected")
            self.assertEqual(db.get(Finding, saved.id).response_id, response.id)
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
