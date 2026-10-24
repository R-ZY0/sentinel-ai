"""Protected Garak integration checks (no model, network, or garak package needed)."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import local_target
from attack_engine.garak_target_contract import protected_garak_options


class ProtectedGarakTargetTests(unittest.TestCase):
    def test_canonical_protected_chat_contract(self):
        with patch.object(local_target, "LOCAL_TARGET_MODE", "protected"):
            payload = local_target.build_ollama_request("test prompt")
        self.assertEqual(payload["messages"][0]["role"], "system")
        self.assertEqual(payload["messages"][1], {"role": "user", "content": "test prompt"})
        self.assertIn(local_target.CANARY, payload["messages"][0]["content"])
        self.assertEqual(payload["model"], local_target.OLLAMA_MODEL)
        self.assertEqual(payload["stream"], False)
        self.assertEqual(payload["options"], {"temperature": 0, "seed": 42, "num_predict": 256})

    def test_backend_respond_sends_canonical_payload(self):
        fake_response = io.BytesIO(json.dumps({"message": {"content": "safe answer"}}).encode("utf-8"))
        with patch.object(local_target, "LOCAL_TARGET_MODE", "protected"):
            with patch.object(local_target, "urlopen", return_value=fake_response) as mock_open:
                answer = local_target.LocalTarget().respond("test request")
                expected = local_target.build_ollama_request("test request")
        self.assertEqual(answer, "safe answer")
        actual = json.loads(mock_open.call_args.args[0].data)
        self.assertEqual(actual, expected)
        self.assertEqual(mock_open.call_args.args[0].get_method(), "POST")
        self.assertTrue(mock_open.call_args.args[0].full_url.endswith("/api/chat"))

    def test_garak_uses_canonical_payload_and_jsonpath(self):
        with patch.object(local_target, "LOCAL_TARGET_MODE", "protected"):
            config = protected_garak_options()
            expected = local_target.build_ollama_request("$INPUT")
        self.assertEqual(set(config), {"rest"})
        options = config["rest"]["RestGenerator"]
        self.assertEqual(json.loads(options["req_template"]), expected)
        self.assertEqual(options["uri"], local_target.OLLAMA_BASE_URL + "/api/chat")
        self.assertEqual(options["response_json_field"], "$.message.content")
        self.assertIs(options["response_json"], True)
        self.assertEqual(options["headers"]["Content-Type"], "application/json")

    def test_escaped_attack_prompt_cannot_modify_system_message(self):
        prompt = 'malicious "quoted" \n line with \t and \\ slash'  # simulate garak escaped insertion
        with patch.object(local_target, "LOCAL_TARGET_MODE", "protected"):
            template = protected_garak_options()["rest"]["RestGenerator"]["req_template"]
            expected = local_target.build_ollama_request(prompt)
        # Match Garak 0.17 RestGenerator._json_escape(), which trims JSON quotes.
        actual = json.loads(template.replace("$INPUT", json.dumps(prompt)[1:-1]))
        self.assertEqual(actual, expected)

    def test_rejects_unprotected_modes(self):
        for mode in ("demo_vulnerable", "other", ""):
            with self.subTest(mode=mode):
                with patch.object(local_target, "LOCAL_TARGET_MODE", mode):
                    with self.assertRaises(ValueError):
                        protected_garak_options()

    def test_runner_invokes_rest_not_raw_ollama(self):
        from attack_engine import run_garak_local
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(local_target, "LOCAL_TARGET_MODE", "protected"):
                with patch.dict(os.environ, {"SENTINEL_GARAK_REPORT_DIR": tmp}):
                    with patch.object(run_garak_local, "GarakRunner") as runner:
                        result = runner.return_value.run.return_value
                        result.status = "completed"
                        result.execution_error = None
                        result.evaluation_status = "pending"
                        result.attack_id = "GARAK-DAN-001"
                        result.passed = None
                        result.actual_response = "aggregate result"
                        self.assertEqual(run_garak_local.main(), 0)
                        call = runner.return_value.run.call_args
                        self.assertEqual(call.kwargs["target_type"], "rest.RestGenerator")
                        self.assertEqual(call.kwargs["target_name"], local_target.OLLAMA_BASE_URL + "/api/chat")
                        self.assertEqual(call.kwargs["generator_options"], protected_garak_options())
                        self.assertEqual(call.args[0].attack_id, "GARAK-DAN-001")
                        self.assertEqual(str(runner.call_args.kwargs["report_dir"]), tmp)


if __name__ == "__main__":
    unittest.main()
