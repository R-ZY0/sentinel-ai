
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from attack_engine.attack_run import AttackRun
from attack_engine.attack_library_runner import run_attack_library


def make_result(status="completed", evaluation_status="fail"):
    return AttackRun(
        attack_id="attack-test-001",
        category="Jailbreak" if evaluation_status == "fail" else "Prompt Injection",
        payload="Authorized test payload",
        target="local-test",
        strategy="unit test",
        expected_behavior="Resist the injection",
        actual_response=(
            "I am an unrestricted assistant." if evaluation_status == "fail"
            else "Safe response"
        ),
        status=status,
    )


class TestAttackLibraryFindingIntegration(unittest.IsolatedAsyncioTestCase):

    async def run_with_result(self, result):
        runner = MagicMock()
        runner.run = AsyncMock(return_value=result)
        repository = MagicMock()

        with patch(
            "attack_engine.attack_library_runner.ATTACK_LIBRARY",
            [MagicMock()],
        ), patch(
            "attack_engine.attack_library_runner.attack_case_to_attack_run",
            return_value=result,
        ):
            results = await run_attack_library(
                runner,
                "local-test",
                finding_repository=repository,
            )

        return results, repository

    async def test_failed_evaluation_saves_finding(self):
        result = make_result()

        results, repository = await self.run_with_result(result)

        self.assertEqual(len(results), 1)
        repository.save.assert_called_once()

        finding = repository.save.call_args.args[0]
        self.assertEqual(finding.attack_id, result.attack_id)
        self.assertEqual(finding.category, result.category)
        self.assertTrue(finding.finding_id.startswith("finding-"))
        self.assertIn("unrestricted", finding.evidence)

    async def test_pass_does_not_save_finding(self):
        result = make_result(evaluation_status="pass")
        result.actual_response = "Safe response"

        results, repository = await self.run_with_result(result)

        repository.save.assert_not_called()

    async def test_prompt_marker_only_does_not_save_finding(self):
        result = make_result(evaluation_status="pass")
        result.actual_response = "PWNED"
        results, repository = await self.run_with_result(result)
        self.assertEqual(results[0].evaluation_status, "not_evaluated")
        repository.save.assert_not_called()

    async def test_execution_failure_does_not_save_finding(self):
        result = make_result(status="failed")
        result.execution_error = "Connection refused"

        results, repository = await self.run_with_result(result)

        self.assertEqual(results[0].evaluation_status, "not_evaluated")
        repository.save.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
