"""Send Garak conversations to an authorized loopback Ollama instance.

This is an isolated transport, not a registered Garak CLI generator.
"""
from urllib.parse import urlsplit

import requests

from attack_engine.garak_conversation_adapter import (
    build_conversation_request,
)


def send_synthetic_conversation(
    conversation, *, model, endpoint="http://127.0.0.1:11434/api/chat",
    timeout=30,
):
    parts = urlsplit(endpoint)

    if (
        parts.scheme != "http"
        or parts.hostname != "127.0.0.1"
        or parts.username is not None
        or parts.password is not None
        or parts.port != 11434
        or parts.netloc != "127.0.0.1:11434"
        or parts.path != "/api/chat"
        or parts.query
        or parts.fragment
    ):
        raise ValueError("Only local Ollama /api/chat is allowed")

    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        raise ValueError("Timeout must be within 1-60 seconds")

    payload = build_conversation_request(
        conversation, model=model, mode="synthetic"
    )

    with requests.Session() as session:
        session.trust_env = False
        response = session.post(
            endpoint,
            json=payload,
            timeout=timeout,
            allow_redirects=False,
        )
        response.raise_for_status()
        data = response.json()
    content = data["message"]["content"]

    if not isinstance(content, str):
        raise ValueError("Invalid Ollama response content")

    return content
