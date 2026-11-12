import unittest
from unittest.mock import AsyncMock

from attack_engine.attack_mutator import mutate_attack_definition
from attack_engine.attack_run import AttackRun
from attack_engine.normalized_attack_adapter import (
    normalized_attack_to_attack_run,
)
from attack_engine.normalized_attack_library import NORMALIZED_ATTACK_LIBRARY
from attack_engine.normalized_attack_runner import run_normalized_attack_library


class TestNormalizedExecution(unittest.IsolatedAsyncioTestCase):

    def test_adapter_preserves_definition_fields(self):
        definition = NORMALIZED_ATTACK_LIBRARY[0]
        result = normalized_attack_to_attack_run(
            definition,
            "Authorized test target",
        )

        self.assertEqual(result.attack_id, definition.attack_id)
        self.assertEqual(result.category, definition.category)
        self.assertEqual(result.payload, definition.payload)
        self.assertEqual(result.target, "Authorized test target")
        self.assertEqual(result.strategy, definition.strategy)
        self.assertEqual(
            result.expected_behavior,
            definition.expected_behavior,
        )
        self.assertEqual(
            result.mutation_strategy,
            definition.mutation_strategy,
        )

    def test_mutation_changes_payload_and_preserves_original(self):
        definition = NORMALIZED_ATTACK_LIBRARY[0]
        original_payload = definition.payload

        mutated = mutate_attack_definition(definition)

        self.assertEqual(mutated.attack_id, definition.attack_id + "-M1")
        self.assertNotEqual(mutated.payload, original_payload)
        self.assertIn(original_payload, mutated.payload)
        self.assertEqual(definition.payload, original_payload)
        self.assertIn(definition.mutation_strategy, mutated.payload)

    def test_mutation_is_deterministic(self):
        definition = NORMALIZED_ATTACK_LIBRARY[0]

        first = mutate_attack_definition(definition)
        second = mutate_attack_definition(definition)

        self.assertEqual(first.payload, second.payload)
        self.assertEqual(first.attack_id, second.attack_id)

    async def test_normalized_runner_executes_original_attacks(self):
        runner = AsyncMock()

        def complete(attack):
            attack.status = "completed"
            attack.actual_response = "I cannot comply with that request."
            return attack

        runner.run.side_effect = complete

        results = await run_normalized_attack_library(
            runner,
            "Authorized test target",
        )

        self.assertEqual(len(results), len(NORMALIZED_ATTACK_LIBRARY))
        self.assertEqual(runner.run.await_count, len(NORMALIZED_ATTACK_LIBRARY))
        self.assertTrue(
            all(not item.attack_id.endswith("-M1") for item in results)
        )

    async def test_normalized_runner_executes_mutations(self):
        runner = AsyncMock()

        def complete(attack):
            attack.status = "completed"
            attack.actual_response = "I cannot comply with that request."
            return attack

        runner.run.side_effect = complete

        results = await run_normalized_attack_library(
            runner,
            "Authorized test target",
            second_round=True,
        )

        self.assertEqual(
            len(results),
            len(NORMALIZED_ATTACK_LIBRARY) * 2,
        )
        self.assertEqual(
            sum(item.attack_id.endswith("-M1") for item in results),
            len(NORMALIZED_ATTACK_LIBRARY),
        )

    async def test_execution_failure_is_not_judged(self):
        runner = AsyncMock()

        def fail(attack):
            attack.status = "failed"
            attack.execution_error = "Simulated target failure"
            return attack

        runner.run.side_effect = fail

        results = await run_normalized_attack_library(
            runner,
            "Authorized test target",
        )

        self.assertTrue(
            all(item.evaluation_status == "not_evaluated" for item in results)
        )
        self.assertTrue(all(item.passed is None for item in results))


    async def test_pending_execution_is_not_judged(self):
        runner = AsyncMock()

        def pending(attack):
            attack.status = "pending"
            attack.actual_response = "Unfinished response"
            return attack

        runner.run.side_effect = pending

        results = await run_normalized_attack_library(
            runner,
            "Authorized test target",
        )

        self.assertTrue(
            all(item.evaluation_status == "not_evaluated" for item in results)
        )
        self.assertTrue(all(item.passed is None for item in results))

    async def test_unknown_execution_status_is_not_judged(self):
        runner = AsyncMock()

        def unknown(attack):
            attack.status = "unknown"
            attack.actual_response = "Unverified response"
            return attack

        runner.run.side_effect = unknown

        results = await run_normalized_attack_library(
            runner,
            "Authorized test target",
        )

        self.assertTrue(
            all(item.evaluation_status == "not_evaluated" for item in results)
        )
        self.assertTrue(all(item.passed is None for item in results))


if __name__ == "__main__":
    unittest.main()
