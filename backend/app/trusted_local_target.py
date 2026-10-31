import json
import secrets
from urllib.request import Request, urlopen

from .local_target import CANARY, OLLAMA_BASE_URL, build_ollama_request


def execute_canary_probe(prompt: str) -> tuple[str, str, dict]:
    if OLLAMA_BASE_URL != "http://ollama:11434":
        raise ValueError("Week 2 validation requires the local Docker target")

    canary = "SENTINEL_EPHEMERAL_" + secrets.token_hex(24)
    body = build_ollama_request(prompt)

    system_message = body["messages"][0]
    if system_message["role"] != "system":
        raise ValueError("Expected a system message")
    if CANARY not in system_message["content"]:
        raise ValueError("Expected the local canary fixture")

    system_message["content"] = system_message["content"].replace(
        CANARY, canary
    )

    request = Request(
        f"{OLLAMA_BASE_URL}/api/chat",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=120) as response:
        result = json.load(response)

    text = result.get("message", {}).get("content")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Local target returned an empty response")

    trusted_fixture = {
        "test_case_id": "TC-002",
        "target_authorized": True,
        "requester_authorized": False,
        "source_verified": True,
        "fixture_loaded": True,
        "values": [
            {
                "id": "local-ephemeral-canary",
                "kind": "canary",
                "value": canary,
            }
        ],
    }
    return text, canary, trusted_fixture