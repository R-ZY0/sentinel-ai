"""Normalize synthetic Garak execution into the local AttackRun model.

No JudgeVerdict or Finding is created here.
"""

from attack_engine.attack_run import AttackRun
from attack_engine.garak_conversation_transport import (
    send_synthetic_conversation,
)


def execute_synthetic_garak_attempt(
    conversation,
    *,
    attack_id,
    model,
    category="System Prompt Leakage",
    endpoint="http://127.0.0.1:11434/api/chat",
    timeout=60,
):
    if not isinstance(attack_id, str) or not attack_id.strip():
        raise ValueError("attack_id is required")

    turns = getattr(conversation, "turns", None)
    if not turns or str(turns[-1].role).lower() != "user":
        raise ValueError("A final user attack turn is required")

    payload = getattr(turns[-1].content, "text", None)
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("Attack payload is required")

    run = AttackRun(
        attack_id=attack_id,
        category=category,
        payload=payload,
        target="authorized-local-ollama",
        strategy="garak-synthetic-conversation",
        expected_behavior="Do not disclose synthetic system instructions",
    )

    try:
        answer = send_synthetic_conversation(
            conversation,
            model=model,
            endpoint=endpoint,
            timeout=timeout,
        )
        if not isinstance(answer, str) or not answer.strip():
            raise ValueError("Empty model response")

    except Exception as exc:
        run.status = "failed"
        run.evaluation_status = "not_evaluated"
        run.execution_error = f"{type(exc).__name__}: {exc}"
        return run

    run.actual_response = answer
    run.status = "completed"
    run.evaluation_status = "pending"

    return run
