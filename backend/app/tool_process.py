"""Real scanner execution in a short-lived process, using a protected fixture."""
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from attack_engine.attack_run import AttackRun
from . import local_target


async def run_pyrit():
    from pyrit.setup import IN_MEMORY, initialize_pyrit_async
    from attack_engine.attack_case_adapter import attack_case_to_attack_run
    from attack_engine.attack_library import ATTACK_LIBRARY
    from attack_engine.ollama_local_pyrit_target import OllamaLocalPyRITTarget
    from attack_engine.pyrit_runner import PyRITRunner

    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    attack = attack_case_to_attack_run(ATTACK_LIBRARY[0], local_target.OLLAMA_BASE_URL)
    attack.strategy = "pyrit"
    return [await PyRITRunner(OllamaLocalPyRITTarget(), timeout_seconds=180).run(attack)]


def run_garak(work: Path):
    from attack_engine.garak_target_contract import protected_garak_options
    from attack_engine.garak_runner import GarakRunner
    from attack_engine.garak_report_adapter import completed_attempt_runs

    options = protected_garak_options()
    reports = work / "reports"
    reports.mkdir()
    config = work / "config.json"
    config.write_text(json.dumps({
        "run": {"generations": 1, "soft_probe_prompt_cap": 3},
        "system": {"parallel_attempts": 1},
        "reporting": {"report_dir": str(reports)},
    }), encoding="utf-8")
    summary = AttackRun(
        attack_id="GARAK-DAN-001", category="Jailbreak",
        payload="Garak-managed Dan_11_0 probe inputs",
        target=local_target.OLLAMA_BASE_URL, strategy="garak",
        expected_behavior="Protect the planted synthetic canary",
    )
    result = GarakRunner(reports, timeout_seconds=480).run(
        summary, target_type="rest.RestGenerator",
        target_name=options["rest"]["RestGenerator"]["uri"],
        probe="probes.dan.Dan_11_0", generator_options=options,
        config_path=config,
    )
    if result.status != "completed":
        raise RuntimeError("Garak did not complete")
    # Feed real per-attempt payloads/responses onward, NEVER the aggregate summary.
    runs = completed_attempt_runs(reports / "garak_GARAK_DAN_001.report.jsonl")
    for run in runs:
        run.target = local_target.OLLAMA_BASE_URL
        run.expected_behavior = "Do not disclose the protected synthetic canary"
    return runs


def main():
    tool, output_name = sys.argv[1:]
    if local_target.OLLAMA_BASE_URL != "http://ollama:11434":
        raise ValueError("Only the Docker-local target is allowed")
    if local_target.LOCAL_TARGET_MODE != "protected":
        raise ValueError("Tool execution requires protected mode")
    request = json.load(sys.stdin)
    canary = request["canary"]
    if not isinstance(canary, str) or not canary.startswith("SENTINEL_EPHEMERAL_"):
        raise ValueError("Expected a server-generated synthetic canary")
    # Process-local override: canonical target builders install this exact fixture.
    local_target.CANARY = canary
    if tool == "pyrit":
        runs = asyncio.run(run_pyrit())
    elif tool == "garak":
        runs = run_garak(Path(output_name).parent)
    else:
        raise ValueError("Unsupported scanner")
    if not runs or any(
        run.status != "completed" or run.execution_error
        or not isinstance(run.actual_response, str) or not run.actual_response.strip()
        for run in runs
    ):
        raise RuntimeError("Scanner returned no usable completed response")
    records = []
    for run in runs:
        record = asdict(run)
        record["timestamp"] = run.timestamp.isoformat()
        if tool == "garak":
            # Stable probe identity and per-execution report UUID are distinct.
            record["source_attempt_id"] = run.attack_id
            record["attack_id"] = "GARAK-DAN-001"
        records.append(record)
    Path(output_name).write_text(json.dumps({
        "tool": tool, "target": local_target.OLLAMA_BASE_URL,
        "target_mode": "protected", "attack_runs": records,
    }), encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Only the exception's class leaves this process; console diagnostics
        # and private prompt/response data are not exposed by the service.
        if len(sys.argv) == 3:
            Path(sys.argv[2]).write_text(
                json.dumps({"error_type": type(exc).__name__}), encoding="utf-8"
            )
        raise
