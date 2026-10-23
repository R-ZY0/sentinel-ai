import json
import unittest

from attack_engine.attack_run import AttackRun
from attack_engine.execution_contract import export_attack_run


def sample():
    return AttackRun(
        attack_id="PI-001",
        category="Prompt Injection",
        payload="Authorized test",
        target="local-ollama",
        strategy="direct",
        expected_behavior="Resist injection",
    )


class TestExecutionContract(unittest.TestCase):

    def test_preserves_attack_case_id(self):
        result = export_attack_run(
            sample(), scan_id="scan-1", target_id="target-1"
        )
        self.assertEqual(result["attack_id"], "PI-001")
        self.assertEqual(result["scan_id"], "scan-1")
        self.assertEqual(result["target_id"], "target-1")

    def test_unique_execution_ids(self):
        a = export_attack_run(
            sample(), scan_id="scan-1", target_id="target-1"
        )
        b = export_attack_run(
            sample(), scan_id="scan-1", target_id="target-1"
        )
        self.assertNotEqual(a["execution_id"], b["execution_id"])

    def test_supplied_execution_id_is_preserved(self):
        result = export_attack_run(
            sample(),
            scan_id="scan-1",
            target_id="target-1",
            execution_id="run-fixed-1",
        )
        self.assertEqual(result["execution_id"], "run-fixed-1")

    def test_json_serializable(self):
        result = export_attack_run(
            sample(), scan_id="scan-1", target_id="target-1"
        )
        self.assertIsInstance(json.dumps(result), str)

    def test_missing_scan_id_rejected(self):
        with self.assertRaises(ValueError):
            export_attack_run(
                sample(), scan_id="", target_id="target-1"
            )

    def test_missing_target_id_rejected(self):
        with self.assertRaises(ValueError):
            export_attack_run(
                sample(), scan_id="scan-1", target_id=""
            )

    def test_original_attack_is_not_mutated(self):
        attack = sample()
        export_attack_run(
            attack, scan_id="scan-1", target_id="target-1"
        )
        self.assertFalse(hasattr(attack, "execution_id"))
        self.assertFalse(hasattr(attack, "scan_id"))


if __name__ == "__main__":
    unittest.main()
