import asyncio
import unittest
from unittest.mock import AsyncMock

from src.attack_library import ATTACK_LIBRARY
from src.attack_library_runner import run_attack_library


class TestReproducibility(unittest.IsolatedAsyncioTestCase):

    async def test_repeated_runs_have_independent_results(self):
        async def fake_run(attack):
            attack.status = "completed"
            attack.actual_response = "Safe response"
            return attack

        runner = type("FakeRunner", (), {})()
        runner.run = AsyncMock(side_effect=fake_run)

        first = await run_attack_library(runner, "local-test")
        second = await run_attack_library(runner, "local-test")

        self.assertEqual(len(first), len(ATTACK_LIBRARY))
        self.assertEqual(len(second), len(ATTACK_LIBRARY))
        self.assertEqual(
            [attack.attack_id for attack in first],
            [attack.attack_id for attack in second],
        )

        for a, b in zip(first, second):
            self.assertIsNot(a, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
