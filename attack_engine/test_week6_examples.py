"""Validate published Week 6 JSON examples against actual local execution."""

import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import unittest

from attack_engine.adaptive import SecondRoundRequest, execute_second_round
from attack_engine.attack_run import AttackRun
from attack_engine.attack_runner import AttackRunner
from attack_engine.attack_schema import AttackDefinition


class PublishedExamplesTests(unittest.TestCase):
    def test_second_round_example_matches_runtime(self):
        examples = Path(__file__).parent / "adaptive" / "examples"
        sample = json.loads((examples / "input.json").read_text(encoding="utf-8"))
        expected = json.loads((examples / "expected_output.json").read_text(encoding="utf-8"))
        request = SecondRoundRequest(
            decision=sample["decision"],
            definition=AttackDefinition(**sample["definition"]),
            target_name=sample["target_name"],
            authorized=sample["authorized"],
            history=tuple(AttackRun(**row) for row in sample["history"]),
            max_attempts=sample["max_attempts"],
            seed=sample["seed"],
        )
        runner = AttackRunner(lambda _: sample["synthetic_target_response"], max_retries=0)
        result = asyncio.run(execute_second_round(request, runner))
        self.assertEqual(result.status, expected["status"])
        self.assertEqual(result.reason, expected["reason"])
        self.assertEqual(asdict(result.variant), expected["variant"])
        self.assertEqual(
            {name: getattr(result.attack_run, name) for name in expected["attack_run"]},
            expected["attack_run"],
        )


if __name__ == "__main__":
    unittest.main()
