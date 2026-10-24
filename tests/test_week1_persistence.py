"""Week-01 data contract regressions, intentionally independent of Ollama/Postgres."""
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
import unittest
from uuid import uuid4
from sqlalchemy import create_engine, inspect, event, select, text
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Scan, Target, AttackAttempt, Response, Finding
from app.attack_persistence import persist_attack_run
from app.schema_migrations import ensure_attack_case_id_column
from attack_engine.backend_contract import attack_run_to_backend_records
from attack_engine.attack_run import AttackRun
from attack_engine.finding_repository import FindingRepository
from attack_engine.finding import Finding as DomainFinding


def fixture_run(status="completed", response="PWNED"):
    return AttackRun(
        attack_id="PI-001", category="Prompt Injection", payload="test probe",
        target="ollama", strategy="test", expected_behavior="refuse",
        status=status, actual_response=response
    )


class TestWeek1Contract(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

        @event.listens_for(self.engine, "connect")
        def keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.scan_id = uuid4()
        self.db.add(Target(id=uuid4(), name="fixture", endpoint="http://ollama:11434"))
        target = self.db.scalars(select(Target)).first()
        self.db.add(Scan(id=self.scan_id, target_id=target.id, status="running"))
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_mapping_keeps_definition_and_execution_ids_separate(self):
        records = attack_run_to_backend_records(
            fixture_run(), scan_id=self.scan_id, attempt_id=uuid4()
        )
        self.assertEqual(records.attempt["attack_case_id"], "PI-001")
        self.assertNotIn("attack_id", records.attempt)

    def test_full_chain_and_repeat_execution_uuids(self):
        a = persist_attack_run(
            self.db, scan_id=self.scan_id, attack=fixture_run(),
            finding_evidence="PWNED"
        )
        b = persist_attack_run(
            self.db, scan_id=self.scan_id, attack=fixture_run(),
            finding_evidence="PWNED"
        )
        self.db.commit()
        self.assertNotEqual(a["attempt_id"], b["attempt_id"])
        self.assertEqual(
            self.db.get(AttackAttempt, a["attempt_id"]).attack_case_id, "PI-001"
        )
        self.assertEqual(
            self.db.get(Response, a["response_id"]).attack_attempt_id,
            a["attempt_id"]
        )
        self.assertEqual(
            self.db.get(Finding, a["finding_id"]).status, "suspected"
        )

    def test_failed_execution_never_creates_response(self):
        ids = persist_attack_run(
            self.db, scan_id=self.scan_id,
            attack=fixture_run("failed", None)
        )
        self.db.commit()
        self.assertIsNone(ids["response_id"])
        self.assertIsNone(ids["finding_id"])

    def test_no_finding_when_response_is_missing(self):
        with self.assertRaises(ValueError):
            persist_attack_run(
                self.db, scan_id=self.scan_id,
                attack=fixture_run("failed", None),
                finding_evidence="should not be saved"
            )
        self.assertEqual(self.db.query(AttackAttempt).count(), 0)

    def test_heuristic_repository_uses_backend_schema(self):
        ids = persist_attack_run(
            self.db, scan_id=self.scan_id, attack=fixture_run()
        )
        finding = DomainFinding(
            "legacy-id", "PI-001", "Prompt Injection", "Test", "High",
            "description", "PWNED"
        )
        saved = FindingRepository(
            self.db, response_id=ids["response_id"]
        ).save(finding)
        self.db.commit()
        self.assertEqual(self.db.get(Finding, saved.id).status, "suspected")

    def test_migration_is_idempotent_on_current_schema(self):
        ensure_attack_case_id_column(self.engine)
        ensure_attack_case_id_column(self.engine)
        columns = {
            column["name"]
            for column in inspect(self.engine).get_columns("attack_attempts")
        }
        self.assertIn("attack_case_id", columns)

    def test_migration_old_schema_retains_rows(self):
        legacy = create_engine("sqlite:///:memory:")
        with legacy.begin() as connection:
            connection.execute(text(
                "CREATE TABLE attack_attempts(id TEXT PRIMARY KEY, category TEXT)"
            ))
            connection.execute(text(
                "INSERT INTO attack_attempts(id, category) "
                "VALUES ('existing-attempt', 'prompt_injection')"
            ))
        ensure_attack_case_id_column(legacy)
        ensure_attack_case_id_column(legacy)
        with legacy.connect() as connection:
            row = connection.execute(text(
                "SELECT id, attack_case_id FROM attack_attempts"
            )).one()
        self.assertEqual(tuple(row), ("existing-attempt", None))
        legacy.dispose()


if __name__ == "__main__":
    unittest.main()
