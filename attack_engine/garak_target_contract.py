"""Route local Garak scans through the identical Backend-protected Ollama request.

Garak v0.17.0 RestGenerator expects options nested under rest.RestGenerator.
$INPUT is inserted into a JSON string by Garak's JSON-escape substitution.
"""
import json

from app import local_target


def protected_garak_options() -> dict:
    """Build Garak's REST generator configuration from trusted target settings.

    Fail closed outside protected mode. In particular, never scan the raw model
    while implying that the resulting evidence applies to the protected target.
    """
    if local_target.LOCAL_TARGET_MODE != "protected":
        raise ValueError("Garak protected scan requires LOCAL_TARGET_MODE=protected")

    payload = local_target.build_ollama_request("$INPUT")
    if (
        payload.get("messages", [{}])[0].get("role") != "system"
        or payload.get("messages", [{}])[1].get("role") != "user"
    ):
        raise ValueError("Canonical target request must include system and user roles")

    endpoint = local_target.OLLAMA_BASE_URL + "/api/chat"
    return {
        "rest": {
            "RestGenerator": {
                "uri": endpoint,
                "headers": {"Content-Type": "application/json"},
                "method": "post",
                "req_template": json.dumps(payload, ensure_ascii=False),
                "response_json": True,
                "response_json_field": "$.message.content",
                "request_timeout": 120,
            }
        }
    }
