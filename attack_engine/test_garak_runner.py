
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

from attack_engine.attack_run import AttackRun
from attack_engine.garak_runner import GarakRunner


def make_attack():
    return AttackRun(
        attack_id="PI-TEST-001",
        category="Prompt Injection",
        payload="Authorized test payload",
        target="local-test",
        strategy="unit-test",
        expected_behavior="The target should resist the injection.",
    )


class TestGarakRunner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.report_dir = Path(self.temp_dir.name)
        self.runner = GarakRunner(
            report_dir=self.report_dir,
            timeout_seconds=5,
            python_executable="python",
        )

    def write_report(self, records, attack_id="PI-TEST-001"):
        prefix = f"garak_{attack_id}".replace("-", "_")
        path = self.report_dir / f"{prefix}.report.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        return path

    @patch("attack_engine.garak_runner.subprocess.run")
    def test_success_reads_aggregate_report_without_per_attack_verdict(
        self, mock_run
    ):
        mock_run.return_value = CompletedProcess(
            args=["python", "-m", "garak"],
            returncode=0,
            stdout="garak complete",
            stderr="",
        )
        self.write_report([
            {
                "entry_type": "eval",
                "passed": 90,
                "fails": 166,
                "total_evaluated": 256,
            }
        ])

        result = self.runner.run(
            make_attack(),
            target_type="ollama.OllamaGenerator",
            target_name="llama3.2:3b",
            probe="probes.promptinject.HijackLongPrompt",
            generator_options={"host": "http://127.0.0.1:11434"},
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.evaluation_status, "pending")
        self.assertIsNone(result.passed)
        self.assertIn("166 detector hits", result.actual_response)
        self.assertIn("256 evaluated samples", result.actual_response)
        self.assertIsNone(result.execution_error)

        command = mock_run.call_args.args[0]
        self.assertIn("--generator_options", command)
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 5)

    @patch("attack_engine.garak_runner.subprocess.run")
    def test_nonzero_exit_is_not_a_security_finding(self, mock_run):
        mock_run.return_value = CompletedProcess(
            args=["python", "-m", "garak"],
            returncode=2,
            stdout="",
            stderr="simulated garak failure",
        )

        result = self.runner.run(
            make_attack(),
            target_type="ollama.OllamaGenerator",
            target_name="llama3.2:3b",
            probe="probes.promptinject.HijackLongPrompt",
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIsNone(result.actual_response)
        self.assertIn("simulated garak failure", result.execution_error)

    @patch("attack_engine.garak_runner.subprocess.run")
    def test_timeout_is_not_a_security_failure(self, mock_run):
        mock_run.side_effect = TimeoutExpired(cmd="garak", timeout=5)

        result = self.runner.run(
            make_attack(),
            target_type="ollama.OllamaGenerator",
            target_name="llama3.2:3b",
            probe="probes.promptinject.HijackLongPrompt",
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIn("timed out", result.execution_error.lower())

    @patch("attack_engine.garak_runner.subprocess.run")
    def test_missing_report_is_not_a_security_failure(self, mock_run):
        mock_run.return_value = CompletedProcess(
            args=["python", "-m", "garak"],
            returncode=0,
            stdout="complete",
            stderr="",
        )

        result = self.runner.run(
            make_attack(),
            target_type="ollama.OllamaGenerator",
            target_name="llama3.2:3b",
            probe="probes.promptinject.HijackLongPrompt",
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIn("Could not read garak report", result.execution_error)

    @patch("attack_engine.garak_runner.subprocess.run")
    def test_report_without_evaluations_is_not_a_security_failure(
        self, mock_run
    ):
        mock_run.return_value = CompletedProcess(
            args=["python", "-m", "garak"],
            returncode=0,
            stdout="complete",
            stderr="",
        )
        self.write_report([{"entry_type": "digest"}])

        result = self.runner.run(
            make_attack(),
            target_type="ollama.OllamaGenerator",
            target_name="llama3.2:3b",
            probe="probes.promptinject.HijackLongPrompt",
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.evaluation_status, "not_evaluated")
        self.assertIsNone(result.passed)
        self.assertIn("no evaluation records", result.execution_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
