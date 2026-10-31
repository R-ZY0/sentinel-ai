import json
import os
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from .tool_service import app


class ToolServiceTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.canary = "SENTINEL_EPHEMERAL_" + "a" * 48

    def tearDown(self):
        self.client.close()

    def test_subprocess_result_is_returned_without_console_output(self):
        def process(command, **kwargs):
            self.assertEqual(json.loads(kwargs["input"])["canary"], self.canary)
            self.assertEqual(command[-2], "garak")
            Path(command[-1]).write_text(json.dumps({"attack_runs": ["controlled"]}))
            return SimpleNamespace(returncode=0, stdout="private scanner console", stderr="")

        with patch.dict(os.environ, {"SENTINEL_TOOL": "garak"}), patch(
            "app.tool_service.subprocess.run", side_effect=process
        ) as run:
            response = self.client.post("/execute", json={"canary": self.canary})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"attack_runs": ["controlled"]})
        self.assertNotIn("private", response.text)
        self.assertFalse(Path(run.call_args.args[0][-1]).exists())

    def test_scanner_failure_is_sanitized(self):
        with patch.dict(os.environ, {"SENTINEL_TOOL": "pyrit"}), patch(
            "app.tool_service.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=self.canary, stderr=self.canary),
        ):
            response = self.client.post("/execute", json={"canary": self.canary})
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(self.canary, response.text)

    def test_scanner_timeout_is_explicit(self):
        with patch.dict(os.environ, {"SENTINEL_TOOL": "pyrit"}), patch(
            "app.tool_service.subprocess.run", side_effect=subprocess.TimeoutExpired("scanner", 600)
        ):
            response = self.client.post("/execute", json={"canary": self.canary})
        self.assertEqual(response.status_code, 504)

    def test_unconfigured_tool_does_not_start_a_process(self):
        with patch.dict(os.environ, {"SENTINEL_TOOL": "unknown"}), patch(
            "app.tool_service.subprocess.run"
        ) as process:
            response = self.client.post("/execute", json={"canary": self.canary})
        self.assertEqual(response.status_code, 503)
        process.assert_not_called()
