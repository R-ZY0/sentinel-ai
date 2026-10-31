"""Week 2 non-breaking AttackRun contract bridge tests."""

import unittest
from uuid import uuid4

from attack_engine.attack_run import AttackRun
from attack_engine.execution_contract import export_attack_run
from attack_engine.backend_contract import attack_run_to_backend_records


def sample():
    return AttackRun(
        attack_id="PI-001",
        category="Prompt Injection",
        payload="Synthetic authorized test",
        target="local-ollama",
        strategy="direct",
        expected_behavior="Reject unauthorized instructions",
        actual_response="Request refused",
        status="completed",
    )


class TestWeek2ContractBridge(unittest.TestCase):

    def test_export_keeps_external_ids_without_mutating_run(self):
        run = sample()

        exported = export_attack_run(
            run,
            scan_id="scan-001",
            target_id="target-001",
            execution_id="execution-001",
        )

        self.assertEqual(exported["attack_id"], "PI-001")
        self.assertEqual(exported["scan_id"], "scan-001")
        self.assertEqual(exported["target_id"], "target-001")
        self.assertEqual(exported["execution_id"], "execution-001")

        self.assertFalse(hasattr(run, "scan_id"))
        self.assertFalse(hasattr(run, "target_id"))
        self.assertEqual(run.attack_id, "PI-001")

    def test_backend_attempt_and_response_relationship(self):
        scan_id = uuid4()
        attempt_id = uuid4()
        target_id = uuid4()

        records = attack_run_to_backend_records(
            sample(),
            scan_id=scan_id,
            attempt_id=attempt_id,
            target_id=target_id,
        )

        self.assertEqual(records.attempt["id"], attempt_id)
        self.assertEqual(records.attempt["scan_id"], scan_id)
        self.assertEqual(records.attempt["attack_case_id"], "PI-001")
        self.assertEqual(records.attempt["category"], "prompt_injection")
        self.assertNotIn("target_id", records.attempt)

        self.assertIsNotNone(records.response)
        self.assertEqual(
            records.response["attack_attempt_id"], attempt_id
        )
        self.assertEqual(records.response["content"], "Request refused")


if __name__ == "__main__":
    unittest.main()
