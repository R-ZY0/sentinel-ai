import io
import json
import unittest
from dataclasses import asdict
from unittest.mock import patch
from urllib.error import URLError

from attack_engine.attack_run import AttackRun
from .tool_client import execute_tool_attacks


class ToolClientTests(unittest.TestCase):
    def payload(self, tool):
        run = AttackRun(
            attack_id="PI-001" if tool == "pyrit" else "GARAK-DAN-001",
            category="Prompt Injection" if tool == "pyrit" else "Jailbreak",
            payload="Actual tool-generated prompt",
            target="http://ollama:11434",
            strategy="pyrit" if tool == "pyrit" else "garak-cli-report",
            expected_behavior="Protect the synthetic canary",
            actual_response="Actual model response", status="completed",
        )
        record = asdict(run)
        record["timestamp"] = run.timestamp.isoformat()
        if tool == "garak":
            record["source_attempt_id"] = "real-report-uuid"
        return {"tool": tool, "target": run.target, "target_mode": "protected",
                "attack_runs": [record]}

    def call(self, tool, payload):
        with patch("app.tool_client.build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            result = execute_tool_attacks(tool)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(request.data)["canary"], result[1])
            self.assertEqual(request.full_url, f"http://{tool}:8080/execute")
            return result

    def test_each_tool_preserves_real_payload_response_and_fixture(self):
        for tool in ("pyrit", "garak"):
            with self.subTest(tool=tool):
                runs, canary, fixture = self.call(tool, self.payload(tool))
                self.assertEqual(runs[0].attack.payload, "Actual tool-generated prompt")
                self.assertEqual(runs[0].attack.actual_response, "Actual model response")
                if tool == "garak":
                    self.assertEqual(runs[0].attack.attack_id, "GARAK-DAN-001")
                    self.assertEqual(runs[0].source_attempt_id, "real-report-uuid")
                self.assertEqual(fixture["values"][0]["value"], canary)
                self.assertTrue(fixture["fixture_loaded"])

    def test_bad_provenance_and_incomplete_records_are_rejected(self):
        for change in ("wrong_target", "wrong_mode", "failed", "empty", "duplicate"):
            with self.subTest(change=change):
                payload = self.payload("garak")
                if change == "wrong_target":
                    payload["target"] = "http://external.invalid"
                elif change == "wrong_mode":
                    payload["target_mode"] = "demo_vulnerable"
                elif change == "failed":
                    payload["attack_runs"][0]["status"] = "failed"
                elif change == "empty":
                    payload["attack_runs"][0]["actual_response"] = ""
                else:
                    payload["attack_runs"] *= 2
                with self.assertRaises(ValueError):
                    self.call("garak", payload)

    def test_service_failure_is_not_an_attack_verdict(self):
        with patch("app.tool_client.build_opener") as opener:
            opener.return_value.open.side_effect = URLError("private internal detail")
            with self.assertRaisesRegex(RuntimeError, "execution service failed"):
                execute_tool_attacks("pyrit")

    def test_unsupported_tool_is_rejected_before_network_access(self):
        with patch("app.tool_client.build_opener") as opener:
            with self.assertRaises(ValueError):
                execute_tool_attacks("unknown")
            opener.assert_not_called()
