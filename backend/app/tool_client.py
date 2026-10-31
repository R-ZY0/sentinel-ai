"""Worker-only boundary to fixed internal scanner services."""
import json
import secrets
from datetime import datetime
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from attack_engine.attack_run import AttackRun
from .local_target import OLLAMA_BASE_URL

TOOL_URLS = {
    "pyrit": "http://pyrit:8080/execute",
    "garak": "http://garak:8080/execute",
}


@dataclass(frozen=True)
class ExecutedToolAttack:
    attack: AttackRun
    source_attempt_id: str | None = None


def execute_tool_attacks(tool: str) -> tuple[list[ExecutedToolAttack], str, dict]:
    if tool not in TOOL_URLS:
        raise ValueError("Unsupported attack tool")
    if OLLAMA_BASE_URL != "http://ollama:11434":
        raise ValueError("Only the Docker-local target is allowed")
    canary = "SENTINEL_EPHEMERAL_" + secrets.token_hex(24)
    request = Request(
        TOOL_URLS[tool],
        data=json.dumps({"canary": canary}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=630) as response:
            payload = json.load(response)
    except HTTPError as exc:
        # The service deliberately returns only a safe operational error class.
        error_type = "ScannerServiceError"
        try:
            detail = json.load(exc).get("detail", {})
            candidate = detail.get("error_type") if isinstance(detail, dict) else None
            if isinstance(candidate, str) and candidate.isidentifier():
                error_type = candidate
        except (ValueError, AttributeError):
            pass
        raise RuntimeError(f"{tool} execution service failed: HTTP {exc.code} ({error_type})") from None
    except (URLError, TimeoutError):
        raise RuntimeError(f"{tool} execution service failed") from None
    if (payload.get("tool") != tool or payload.get("target") != OLLAMA_BASE_URL
            or payload.get("target_mode") != "protected"):
        raise ValueError("Scanner response has unexpected target provenance")
    records = payload.get("attack_runs")
    if not isinstance(records, list) or not records:
        raise ValueError("Scanner returned no attack records")
    runs = []
    seen = set()
    for record in records:
        record = dict(record)
        source_id = record.pop("source_attempt_id", None)
        record["timestamp"] = datetime.fromisoformat(record["timestamp"])
        run = AttackRun(**record)
        if (run.status != "completed" or run.execution_error
                or run.target != OLLAMA_BASE_URL
                or not isinstance(run.payload, str) or not run.payload.strip()
                or not isinstance(run.actual_response, str) or not run.actual_response.strip()
                or run.evaluation_status != "pending"):
            raise ValueError("Scanner returned an invalid completed attack")
        if tool == "garak" and (
            run.attack_id != "GARAK-DAN-001" or not isinstance(source_id, str) or not source_id.strip()
        ):
            raise ValueError("Garak probe identity or report attempt identifier is missing")
        identity = (run.attack_id, source_id)
        if identity in seen:
            raise ValueError("Scanner returned duplicate attack identifiers")
        if run.strategy != {"pyrit": "pyrit", "garak": "garak-cli-report"}[tool]:
            raise ValueError("Scanner returned an unexpected execution strategy")
        seen.add(identity)
        runs.append(ExecutedToolAttack(run, source_id))
    fixture = {
        "test_case_id": "TC-002", "target_authorized": True,
        "requester_authorized": False, "source_verified": True,
        "fixture_loaded": True,
        "values": [{"id": f"{tool}-ephemeral-canary", "kind": "canary", "value": canary}],
    }
    return runs, canary, fixture
