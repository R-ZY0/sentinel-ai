"""Regression tests for the local Ollama bridge."""

import unittest
from unittest.mock import MagicMock, patch

from attack_engine.run_pyrit_local import LocalOllamaBridge


class TestLocalOllamaBridge(unittest.TestCase):

    @patch("attack_engine.run_pyrit_local.OllamaTarget")
    def test_uses_local_ollama(self, target_class):
        bridge = LocalOllamaBridge()

        target_class.assert_called_once_with(
            model="llama3.2:3b",
            url="http://127.0.0.1:11434/api/generate",
        )

    @patch("attack_engine.run_pyrit_local.OllamaTarget")
    def test_returns_actual_response(self, target_class):
        target_class.return_value.send.return_value = "PWNED"

        bridge = LocalOllamaBridge()
        response = bridge.respond("test prompt")

        self.assertEqual(response, "PWNED")
        target_class.return_value.send.assert_called_once_with(
            "test prompt"
        )

    @patch("attack_engine.run_pyrit_local.OllamaTarget")
    def test_propagates_connection_error(self, target_class):
        target_class.return_value.send.side_effect = ConnectionError(
            "Ollama unavailable"
        )

        bridge = LocalOllamaBridge()

        with self.assertRaises(ConnectionError):
            bridge.respond("test prompt")


if __name__ == "__main__":
    unittest.main()
