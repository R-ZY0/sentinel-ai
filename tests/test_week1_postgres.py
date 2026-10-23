"""PostgreSQL acceptance check for the real Week-01 ORM and persistence.

Requires a dedicated disposable test DB, provided by GitHub Actions service.
"""
import os
import unittest
from uuid import uuid4
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.models import Base, Target, Scan, AttackAttempt, Response, Finding
from app.schema_migrations import ensure_attack_case_id_column
from app.attack_persistence import persist_attack_run
from attack_engine.attack_run import AttackRun


class TestPostgresWeek1Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        url = os.getenv("DATABASE_URL", "")
        if not url.startswith("postgresql+psycopg://"):
            raise unittest.SkipTest("This test needs a disposable PostgreSQL database.")
        cls.engine = create_engine(url, pool_pre_ping=True)
        Base.metadata.create_all(cls.engine)
        ensure_attack_case_id_column(cls.engine)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def test_persist_and_read_from_fresh_session(self):
        case = f"PI-{uuid4().hex[:10]}"
        with Session(self.engine) as db:
            target = Target(name="ci-synthetic", endpoint="http://ollama:11434/")
            db.add(target)
            db.flush()
            scan = Scan(target_id=target.id, status="running")
            db.add(scan)
            db.flush()
            attack = AttackRun(
                attack_id=case, category="Prompt Injection",
                payload="Synthetic CI probe", target="ci-only",
                strategy="test", expected_behavior="refuse",
                actual_response="PWNED", status="completed"
            )
            ids = persist_attack_run(
                db, scan_id=scan.id, attack=attack, finding_evidence="PWNED"
            )
            saved_scan_id = scan.id
            saved_target_id = target.id
            db.commit()

        with Session(self.engine) as db:
            self.assertEqual(
                db.get(AttackAttempt, ids["attempt_id"]).attack_case_id, case
            )
            self.assertEqual(
                db.get(Response, ids["response_id"]).attack_attempt_id,
                ids["attempt_id"]
            )
            finding = db.get(Finding, ids["finding_id"])
            self.assertEqual(finding.status, "suspected")
            self.assertEqual(finding.response_id, ids["response_id"])
            db.delete(finding)
            db.delete(db.get(Response, ids["response_id"]))
            db.delete(db.get(AttackAttempt, ids["attempt_id"]))
            db.delete(db.get(Scan, saved_scan_id))
            db.delete(db.get(Target, saved_target_id))
            db.commit()

    def test_idempotent_schema_migration(self):
        ensure_attack_case_id_column(self.engine)
        ensure_attack_case_id_column(self.engine)


if __name__ == "__main__":
    unittest.main()
