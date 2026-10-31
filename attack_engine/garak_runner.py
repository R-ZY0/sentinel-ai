
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from attack_engine.attack_run import AttackRun


class GarakRunner:
    """Run garak and safely map aggregate results to an AttackRun."""

    def __init__(
        self,
        report_dir: Path,
        timeout_seconds: int = 300,
        python_executable: Optional[str] = None,
        generations: int = 1,
        parallel_attempts: int = 1,
    ):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        if generations <= 0:
            raise ValueError("generations must be greater than zero.")
        if parallel_attempts <= 0:
            raise ValueError("parallel_attempts must be greater than zero.")

        self.report_dir = Path(report_dir)
        self.timeout_seconds = timeout_seconds
        self.python_executable = python_executable or sys.executable
        self.generations = generations
        self.parallel_attempts = parallel_attempts

    def run(
        self,
        attack: AttackRun,
        target_type: str,
        target_name: str,
        probe: str,
        generator_options: Optional[dict] = None,
        config_path: Optional[Path] = None,
    ) -> AttackRun:
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return self._execution_failure(
                attack,
                f"Could not create report directory: {type(exc).__name__}: {exc}",
            )

        report_prefix = f"garak_{attack.attack_id}".replace("-", "_")

        command = [
            self.python_executable,
            "-m",
            "garak",
            "--target_type",
            target_type,
            "--target_name",
            target_name,
            "--spec",
            probe,
            "--generations",
            str(self.generations),
            "--parallel_attempts",
            str(self.parallel_attempts),
            "--report_prefix",
            report_prefix,
        ]

        if config_path is not None:
            command.extend(["--config", str(config_path)])

        if generator_options:
            command.extend(
                ["--generator_options", json.dumps(generator_options)]
            )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                cwd=str(self.report_dir),
            )
        except subprocess.TimeoutExpired:
            return self._execution_failure(
                attack,
                f"garak timed out after {self.timeout_seconds} seconds.",
            )
        except Exception as exc:
            return self._execution_failure(
                attack,
                f"{type(exc).__name__}: {exc}",
            )

        if completed.returncode != 0:
            details = completed.stderr.strip() or completed.stdout.strip()
            return self._execution_failure(
                attack,
                f"garak exited with code {completed.returncode}: {details}",
            )

        report_path = self.report_dir / f"{report_prefix}.report.jsonl"

        try:
            records = [
                json.loads(line)
                for line in report_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, json.JSONDecodeError) as exc:
            return self._execution_failure(
                attack,
                f"Could not read garak report: {type(exc).__name__}: {exc}",
            )

        evaluations = [
            record
            for record in records
            if record.get("entry_type") == "eval"
        ]

        if not evaluations:
            return self._execution_failure(
                attack,
                "The garak report contains no evaluation records.",
            )

        try:
            total = sum(
                int(item.get("total_evaluated", 0))
                for item in evaluations
            )
            failures = sum(
                int(item.get("fails", 0))
                for item in evaluations
            )
            passed_count = sum(
                int(item.get("passed", 0))
                for item in evaluations
            )
        except (TypeError, ValueError) as exc:
            return self._execution_failure(
                attack,
                f"Invalid evaluation data in garak report: {exc}",
            )

        if total <= 0:
            return self._execution_failure(
                attack,
                "The garak report contains no evaluated samples.",
            )

        attack.status = "completed"
        attack.execution_error = None
        attack.actual_response = (
            f"Garak aggregate result: {failures} detector hits, "
            f"{passed_count} passes, {total} evaluated samples. "
            f"Probe: {probe}. These are aggregate scanner results, "
            "not an individual payload response."
        )
        attack.evaluation_status = "pending"
        attack.passed = None
        attack.judge_reason = (
            "Garak completed successfully. Aggregate detector results "
            "require separate interpretation. No per-attack verdict "
            "or confirmed vulnerability was assigned."
        )

        return attack

    @staticmethod
    def _execution_failure(
        attack: AttackRun,
        message: str,
    ) -> AttackRun:
        attack.status = "failed"
        attack.actual_response = None
        attack.execution_error = message
        attack.evaluation_status = "not_evaluated"
        attack.passed = None
        attack.judge_reason = (
            "Garak execution or report processing failed; "
            "the attack cannot be evaluated."
        )
        return attack
