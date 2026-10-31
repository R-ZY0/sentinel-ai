import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from attack_engine.attack_run import AttackRun
from . import local_target, tool_process


class ToolProcessTests(unittest.TestCase):
    def invoke(self, tool, *, valid_response=True):
        canary = "SENTINEL_EPHEMERAL_" + "b" * 48

        def execute(*args):
            request = local_target.build_ollama_request("Actual scanner prompt")
            self.assertIn(canary, request["messages"][0]["content"])
            self.assertNotIn(canary, request["messages"][1]["content"])
            return [AttackRun(
                attack_id="PI-001", category="Prompt Injection",
                payload="Actual scanner prompt", target=local_target.OLLAMA_BASE_URL,
                strategy="pyrit", expected_behavior="Protect the canary",
                actual_response="Actual scanner reply" if valid_response else None,
                status="completed" if valid_response else "failed",
            )]

        scanner = AsyncMock(side_effect=execute) if tool == "pyrit" else execute
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            with (
                patch.object(local_target, "OLLAMA_BASE_URL", "http://ollama:11434"),
                patch.object(local_target, "LOCAL_TARGET_MODE", "protected"),
                patch.object(local_target, "CANARY", "legacy-test-fixture"),
                patch.object(tool_process.sys, "argv", ["tool_process", tool, str(output)]),
                patch.object(tool_process.sys, "stdin", io.StringIO(json.dumps({"canary": canary}))),
                patch.object(tool_process, "run_" + tool, scanner),
            ):
                if valid_response:
                    tool_process.main()
                    result = json.loads(output.read_text())
                    self.assertEqual(result["tool"], tool)
                    self.assertEqual(result["attack_runs"][0]["actual_response"], "Actual scanner reply")
                else:
                    with self.assertRaisesRegex(RuntimeError, "no usable completed response"):
                        tool_process.main()
                    self.assertFalse(output.exists())

    def test_both_processes_install_the_exact_fixture_before_execution(self):
        for tool in ("pyrit", "garak"):
            with self.subTest(tool=tool):
                self.invoke(tool)

    def test_failed_execution_never_exports_a_completed_attack(self):
        self.invoke("pyrit", valid_response=False)

    def test_unprotected_target_is_rejected_before_scanner_execution(self):
        with (
            patch.object(tool_process.sys, "argv", ["tool_process", "pyrit", "unused.json"]),
            patch.object(local_target, "OLLAMA_BASE_URL", "http://ollama:11434"),
            patch.object(local_target, "LOCAL_TARGET_MODE", "demo_vulnerable"),
            patch.object(tool_process, "run_pyrit") as scanner,
        ):
            with self.assertRaisesRegex(ValueError, "protected mode"):
                tool_process.main()
            scanner.assert_not_called()
