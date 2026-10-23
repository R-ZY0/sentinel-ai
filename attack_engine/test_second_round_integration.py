import unittest
from unittest.mock import AsyncMock, patch

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_run import AttackRun
from attack_engine.attack_library_runner import run_attack_library


class TestSecondRoundIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_default_runs_original_attacks_only(self):
        runner = AsyncMock()
        runner.run.side_effect = lambda attack: self.completed(attack)

        results = await run_attack_library(runner, "Test target")

        self.assertEqual(len(results), len(ATTACK_LIBRARY))
        self.assertTrue(all(not item.attack_id.endswith("-R2") for item in results))

    async def test_second_round_runs_original_and_mutated_attacks(self):
        runner = AsyncMock()
        runner.run.side_effect = lambda attack: self.completed(attack)

        results = await run_attack_library(
            runner,
            "Test target",
            second_round=True,
        )

        self.assertEqual(len(results), len(ATTACK_LIBRARY) * 2)
        self.assertEqual(
            sum(item.attack_id.endswith("-R2") for item in results),
            len(ATTACK_LIBRARY),
        )

    @staticmethod
    def completed(attack):
        attack.actual_response = "I cannot follow that request."
        attack.status = "completed"
        return attack


if __name__ == "__main__":
    unittest.main()
