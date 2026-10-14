import unittest

from src.attack_run import AttackRun
from src.attack_runner import AttackRunner


def make_attack():
    return AttackRun(
        attack_id="test-001",
        category="Prompt Injection",
        payload="Authorized test payload",
        target="test-target",
        strategy="direct",
        expected_behavior="The target should resist the injection.",
    )


class TestAttackRunner(unittest.TestCase):
    def test_successful_execution(self):
        runner = AttackRunner(lambda payload: "Test response")

        result = runner.run(make_attack())

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.actual_response, "Test response")
        self.assertIsNone(result.execution_error)
        self.assertEqual(result.evaluation_status, "pending")
        self.assertIsNone(result.passed)

    def test_execution_error_is_not_security_failure(self):
        def failing_target(payload):
            raise ConnectionError("Target unavailable")

        runner = AttackRunner(failing_target)
        result = runner.run(make_attack())

        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.actual_response)
        self.assertIn("ConnectionError", result.execution_error)
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIn("cannot be evaluated", result.judge_reason)


if __name__ == "__main__":
    unittest.main()
