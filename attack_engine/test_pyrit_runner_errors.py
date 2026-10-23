import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from attack_engine.attack_run import AttackRun
from attack_engine.pyrit_runner import PyRITRunner


def make_attack():
    return AttackRun(
        attack_id="PI-TEST-001",
        category="Prompt Injection",
        payload="Authorized test payload",
        target="local-test",
        strategy="unit-test",
        expected_behavior="The target should resist the injection.",
    )


class TestPyRITRunnerErrors(unittest.IsolatedAsyncioTestCase):

    async def test_timeout_is_not_a_security_failure(self):
        fake_attack = MagicMock()
        fake_attack.execute_async = AsyncMock(
            side_effect=asyncio.TimeoutError()
        )

        with patch(
            "attack_engine.pyrit_runner.PromptSendingAttack",
            return_value=fake_attack,
        ):
            runner = PyRITRunner(
                target=MagicMock(),
                timeout_seconds=1,
            )
            result = await runner.run(make_attack())

        self.assertEqual(result.status, "failed")
        self.assertIn("timed out", result.execution_error.lower())
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIsNone(result.actual_response)

    async def test_execution_exception_is_not_a_security_failure(self):
        fake_attack = MagicMock()
        fake_attack.execute_async = AsyncMock(
            side_effect=ConnectionError("Simulated connection failure")
        )

        with patch(
            "attack_engine.pyrit_runner.PromptSendingAttack",
            return_value=fake_attack,
        ):
            runner = PyRITRunner(
                target=MagicMock(),
                timeout_seconds=5,
            )
            result = await runner.run(make_attack())

        self.assertEqual(result.status, "failed")
        self.assertIn("ConnectionError", result.execution_error)
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIsNone(result.actual_response)


if __name__ == "__main__":
    unittest.main(verbosity=2)
