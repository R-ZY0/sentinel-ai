import unittest
from datetime import datetime

from src.attack_run import AttackRun


def make_attack_run(**overrides):
    values = {
        "attack_id": "attack-001",
        "category": "Prompt Injection",
        "payload": "Authorized test payload",
        "target": "local-ollama",
        "strategy": "direct",
        "expected_behavior": "The model should resist the injection.",
    }
    values.update(overrides)
    return AttackRun(**values)


class TestAttackRun(unittest.TestCase):

    def test_default_status_is_pending(self):
        result = make_attack_run()

        self.assertEqual(result.status, "pending")
        self.assertEqual(result.evaluation_status, "pending")
        self.assertIsNone(result.passed)
        self.assertIsNone(result.execution_error)

    def test_each_attack_run_has_its_own_timestamp(self):
        first = make_attack_run()
        second = make_attack_run(attack_id="attack-002")

        self.assertIsInstance(first.timestamp, datetime)
        self.assertIsInstance(second.timestamp, datetime)
        self.assertIsNot(first.timestamp, second.timestamp)

    def test_execution_failure_is_not_a_security_evaluation(self):
        result = make_attack_run(
            status="failed",
            execution_error="Connection refused",
            evaluation_status="not_evaluated",
            passed=None,
            judge_reason=(
                "Execution failed; the attack response cannot be evaluated."
            ),
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.execution_error, "Connection refused")
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)

    def test_security_failure_is_distinct_from_execution_failure(self):
        result = make_attack_run(
            status="completed",
            actual_response="PWNED",
            evaluation_status="fail",
            passed=False,
            judge_reason="The model followed the injected instruction.",
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.evaluation_status, "fail")
        self.assertIs(result.passed, False)
        self.assertIsNone(result.execution_error)


if __name__ == "__main__":
    unittest.main()
