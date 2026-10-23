import ast
import unittest
from pathlib import Path
from uuid import UUID, uuid4

from attack_engine.attack_run import AttackRun
from attack_engine.backend_contract import (
    as_uuid,
    normalize_category,
    attack_run_to_backend_records,
)


def make_run(
    status="completed",
    response="SAFE_OK",
    category="Prompt Injection",
):
    return AttackRun(
        attack_id="PI-001",
        category=category,
        payload="Authorized local test",
        target="local-ollama",
        strategy="direct",
        expected_behavior="Resist injection",
        actual_response=response,
        status=status,
    )


class TestBackendContract(unittest.TestCase):

    def test_uuid_conversion(self):
        value = uuid4()
        self.assertEqual(as_uuid(str(value), "id"), value)
        self.assertEqual(as_uuid(value, "id"), value)

    def test_invalid_uuid_rejected(self):
        with self.assertRaises(ValueError):
            as_uuid("not-a-uuid", "scan_id")

    def test_category_normalization(self):
        self.assertEqual(
            normalize_category("Prompt Injection"),
            "prompt_injection",
        )
        self.assertEqual(
            normalize_category("Data Leakage"),
            "data_leakage",
        )

    def test_completed_attack_mapping(self):
        scan_id, attempt_id, target_id = uuid4(), uuid4(), uuid4()

        records = attack_run_to_backend_records(
            make_run(),
            scan_id=scan_id,
            attempt_id=attempt_id,
            target_id=target_id,
        )

        self.assertEqual(records.attempt["id"], attempt_id)
        self.assertEqual(records.attempt["scan_id"], scan_id)
        self.assertEqual(records.attempt["attack_id"], "PI-001")
        self.assertEqual(
            records.attempt["category"],
            "prompt_injection",
        )
        self.assertEqual(records.attempt["status"], "completed")
        self.assertEqual(
            records.response["attack_attempt_id"],
            attempt_id,
        )
        self.assertEqual(records.response["content"], "SAFE_OK")

    def test_failed_execution_has_no_response(self):
        records = attack_run_to_backend_records(
            make_run(status="failed", response=None),
            scan_id=uuid4(),
            attempt_id=uuid4(),
        )

        self.assertEqual(records.attempt["status"], "failed")
        self.assertIsNone(records.response)

    def test_completed_without_response_rejected(self):
        with self.assertRaises(ValueError):
            attack_run_to_backend_records(
                make_run(response=None),
                scan_id=uuid4(),
                attempt_id=uuid4(),
            )

    def test_identifiers_are_separate(self):
        scan_id, attempt_id = uuid4(), uuid4()
        records = attack_run_to_backend_records(
            make_run(),
            scan_id=scan_id,
            attempt_id=attempt_id,
        )
        self.assertNotEqual(scan_id, attempt_id)
        self.assertNotIn("target_id", records.attempt)
        self.assertNotIn("execution_id", records.attempt)

    def test_actual_backend_model_shapes(self):
        """Compare against the team's actual SQLAlchemy model source."""
        root = Path(__file__).resolve().parent.parent
        source_file = root / "backend" / "app" / "models.py"
        if not source_file.is_file():
            self.fail("Backend models.py missing")

        tree = ast.parse(
            source_file.read_text(encoding="utf-8-sig")
        )

        classes = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        }

        for name in ("Scan", "AttackAttempt", "Response"):
            self.assertIn(name, classes)

        def names(cls):
            return {
                n.target.id
                for n in classes[cls].body
                if isinstance(n, ast.AnnAssign)
                and isinstance(n.target, ast.Name)
            }

        scan_fields = names("Scan")
        attempt_fields = names("AttackAttempt")
        response_fields = names("Response")

        self.assertIn("target_id", scan_fields)

        self.assertTrue({
            "id", "scan_id", "attack_id",
            "category", "payload", "status",
        }.issubset(attempt_fields))

        self.assertTrue({
            "attack_attempt_id", "content"
        }.issubset(response_fields))

        result = attack_run_to_backend_records(
            make_run(),
            scan_id=uuid4(),
            attempt_id=uuid4(),
        )

        self.assertTrue(set(result.attempt).issubset(attempt_fields))
        self.assertTrue(set(result.response).issubset(response_fields))


if __name__ == "__main__":
    unittest.main()
