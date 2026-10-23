"""Run an authorized Garak probe against local Ollama."""

import json
import sys
import tempfile
from pathlib import Path

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_case_adapter import attack_case_to_attack_run
from attack_engine.garak_runner import GarakRunner


def main():
    work = Path(tempfile.mkdtemp(prefix="sentinel_garak_"))
    reports = work / "reports"
    reports.mkdir()

    config = {
        "run": {
            "generations": 1,
            "soft_probe_prompt_cap": 3,
        },
        "system": {
            "parallel_attempts": 1,
        },
        "reporting": {
            "report_dir": str(reports),
        },
    }

    config_path = work / "garak_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    attack = attack_case_to_attack_run(
        ATTACK_LIBRARY[0], "local-ollama"
    )

    runner = GarakRunner(
        report_dir=reports,
        python_executable=sys.executable,
        timeout_seconds=300,
        generations=1,
        parallel_attempts=1,
    )

    result = runner.run(
        attack,
        target_type="ollama.OllamaGenerator",
        target_name="llama3.2:3b",
        probe="probes.dan.Dan_11_0",
        config_path=config_path,
    )

    print("=== GARAK PROJECT RUNNER ===")
    print("Attack ID:", result.attack_id)
    print("Status:", result.status)
    print("Evaluation:", result.evaluation_status)
    print("Passed:", result.passed)
    print("Response:", result.actual_response)
    print("Error:", result.execution_error)
    print("Report directory:", reports)

    if (
        result.status == "completed"
        and result.execution_error is None
        and result.evaluation_status == "pending"
    ):
        print("GARAK PROJECT INTEGRATION: PASS")
        return 0

    print("GARAK PROJECT INTEGRATION: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
