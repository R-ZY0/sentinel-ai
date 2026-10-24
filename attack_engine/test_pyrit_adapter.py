
import unittest

from pyrit.executor.attack.single_turn.prompt_sending import AttackResult
from pyrit.models.messages import MessagePiece
from pyrit.models.results.attack_result import AttackOutcome

from attack_engine.pyrit_adapter import pyrit_result_to_attack_run


class TestPyRITAdapter(unittest.TestCase):

    def test_successful_result_is_converted(self):
        response = MessagePiece(
            role="assistant",
            original_value="PYRIT_OLLAMA_OK",
        )

        result = AttackResult(
            conversation_id="conversation-test",
            objective="Test prompt",
            attack_result_id="attack-test",
            last_response=response,
            outcome=AttackOutcome.UNDETERMINED,
        )

        converted = pyrit_result_to_attack_run(
            result=result,
            category="Prompt Injection",
            target="local-test",
            strategy="unit-test",
            expected_behavior="The model should respond normally.",
        )

        self.assertEqual(converted.attack_id, "attack-test")
        self.assertEqual(converted.actual_response, "PYRIT_OLLAMA_OK")
        self.assertEqual(converted.status, "completed")
        self.assertEqual(converted.evaluation_status, "pending")
        self.assertIsNone(converted.execution_error)

    def test_original_attack_id_is_preserved(self):
        result = AttackResult(
            conversation_id="conversation-test",
            objective="Test prompt",
            attack_result_id="pyrit-generated-id",
            outcome=AttackOutcome.UNDETERMINED,
        )

        converted = pyrit_result_to_attack_run(
            result=result,
            category="Prompt Injection",
            target="local-test",
            strategy="unit-test",
            expected_behavior="The model should follow its intended instructions.",
            original_attack_id="PI-001",
        )

        self.assertEqual(converted.attack_id, "PI-001")

    def test_execution_error_is_not_a_security_failure(self):
        result = AttackResult(
            conversation_id="conversation-test",
            objective="Test prompt",
            attack_result_id="attack-error",
            outcome=AttackOutcome.ERROR,
            error_message="Simulated connection error",
        )

        converted = pyrit_result_to_attack_run(
            result=result,
            category="Prompt Injection",
            target="local-test",
            strategy="unit-test",
            expected_behavior="The model should respond normally.",
            original_attack_id="PI-002",
        )

        self.assertEqual(converted.attack_id, "PI-002")
        self.assertEqual(converted.status, "failed")
        self.assertEqual(converted.evaluation_status, "not_evaluated")
        self.assertIsNone(converted.passed)
        self.assertEqual(
            converted.execution_error,
            "Simulated connection error",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)