"""Read completed Garak report attempts into local AttackRun objects.

This adapter does not assign security verdicts or create Findings.
"""
import json
from pathlib import Path

from garak.attempt import ATTEMPT_COMPLETE
from attack_engine.attack_run import AttackRun


def completed_attempt_runs(report_path, *, category="Jailbreak"):
    path = Path(report_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    completed = {}
    seen = set()

    with path.open("r", encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue

            record = json.loads(line)

            if record.get("entry_type") != "attempt":
                continue

            uid = record.get("uuid")
            if not isinstance(uid, str) or not uid.strip():
                raise ValueError(f"Missing UUID at line {number}")

            if record.get("status") != ATTEMPT_COMPLETE:
                continue

            if uid in seen:
                raise ValueError(f"Duplicate completed UUID at line {number}")

            seen.add(uid)
            completed[uid] = record

    runs = []

    for uid, record in completed.items():
        outputs = record.get("outputs")

        if not isinstance(outputs, list) or not outputs:
            raise ValueError("Completed attempt missing outputs")

        responses = []
        for output in outputs:
            if not isinstance(output, dict):
                raise ValueError("Invalid output entry")
            response = output.get("text")
            if not isinstance(response, str) or not response.strip():
                raise ValueError("Missing output text")
            responses.append(response)

        prompt = record.get("prompt")
        if isinstance(prompt, dict):
            prompt_text = prompt.get("text")
            if not isinstance(prompt_text, str):
                prompt_text = json.dumps(prompt, ensure_ascii=False)
        elif isinstance(prompt, str):
            prompt_text = prompt
        else:
            raise ValueError("Unsupported prompt type")

        if not prompt_text.strip():
            raise ValueError("Empty prompt")

        run = AttackRun(
            attack_id=uid,
            category=category,
            payload=prompt_text,
            target="authorized-local-ollama",
            strategy="garak-cli-report",
            expected_behavior="Resist synthetic security probes",
        )
        run.actual_response = "\n".join(responses)
        run.status = "completed"
        run.evaluation_status = "pending"
        runs.append(run)

    return runs
