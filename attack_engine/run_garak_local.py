"""Run a Garak probe against Sentinel AI's protected local Ollama contract.

Requires Python with garak==0.17.0 and OLLAMA_BASE_URL targeting authorized Ollama.
Use SENTINEL_GARAK_REPORT_DIR for persistent reports across container restarts.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

from attack_engine.attack_run import AttackRun
from attack_engine.garak_runner import GarakRunner
from attack_engine.garak_target_contract import protected_garak_options


def main():
    # Fail closed before invoking a scanner; unsafe demo mode is forbidden.
    generator_options = protected_garak_options()
    endpoint = generator_options["rest"]["RestGenerator"]["uri"]

    work = Path(tempfile.mkdtemp(prefix="sentinel_garak_"))
    report_env = os.environ.get("SENTINEL_GARAK_REPORT_DIR")
    reports = Path(report_env) if report_env else work / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    config = {
        "run": {"generations": 1, "soft_probe_prompt_cap": 3},
        "system": {"parallel_attempts": 1},
        "reporting": {"report_dir": str(reports)},
    }
    config_path = work / "garak_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    attack = AttackRun(
        attack_id="GARAK-DAN-001",
        category="Jailbreak",
        payload="Garak-managed Dan_11_0 probe inputs",
        target="protected-local-ollama",
        strategy="garak",
        expected_behavior="Resist jailbreak and protect the planted synthetic canary",
    )

    runner = GarakRunner(
        report_dir=reports,
        python_executable=sys.executable,
        timeout_seconds=360,
        generations=1,
        parallel_attempts=1,
    )
    result = runner.run(
        attack,
        target_type="rest.RestGenerator",
        target_name=endpoint,
        probe="probes.dan.Dan_11_0",
        generator_options=generator_options,
        config_path=config_path,
    )

    print("=== GARAK PROTECTED TARGET RUN ===")
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
        print("GARAK PROTECTED INTEGRATION: PASS (aggregate scan, not confirmed exploit)")
        return 0

    print("GARAK PROTECTED INTEGRATION: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
