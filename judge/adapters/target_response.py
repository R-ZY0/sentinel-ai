"""Judge-owned adapter; does not change or define cross-team contracts."""
from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any


@dataclass(frozen=True)
class TargetResponseInput:
    response: str
    attack: str
    expected_behavior: str
    attack_id: str | None = None
    status: str | None = None
    timestamp: str | None = None
    latency: float | None = None


def normalize_target_response(
    payload: Mapping[str, Any], *, attack: str | None = None,
    expected_behavior: str | None = None,
) -> TargetResponseInput:
    """Accept a shared-style TargetResponse or Week-1 captured scan row.

    The strings required by LLM/Hybrid must be provided in payload or kwargs.
    No attacks, database access, or side effects are performed.
    """
    if not isinstance(payload, Mapping):
        raise TypeError("target response must be a mapping")
    response = payload.get("response")
    if not isinstance(response, str) or not response.strip():
        raise ValueError("response must be a non-empty string")
    attack_value = attack if attack is not None else payload.get("attack", payload.get("prompt"))
    expected_value = (expected_behavior if expected_behavior is not None
                      else payload.get("expected_behavior"))
    if not isinstance(attack_value, str) or not attack_value.strip():
        raise ValueError("attack or prompt must be a non-empty string")
    if not isinstance(expected_value, str) or not expected_value.strip():
        raise ValueError("expected_behavior must be a non-empty string")
    attack_id = payload.get("attack_id", payload.get("case_id"))
    status, timestamp, latency = (payload.get(k) for k in ("status", "timestamp", "latency"))
    if attack_id is not None and not isinstance(attack_id, str):
        raise TypeError("attack_id must be a string or None")
    if status is not None and not isinstance(status, str):
        raise TypeError("status must be a string or None")
    if timestamp is not None and not isinstance(timestamp, str):
        raise TypeError("timestamp must be a string or None")
    if latency is not None and (isinstance(latency, bool) or not isinstance(latency, (int, float)) or latency < 0):
        raise ValueError("latency must be a non-negative number or None")
    return TargetResponseInput(response=response, attack=attack_value,
                               expected_behavior=expected_value, attack_id=attack_id,
                               status=status, timestamp=timestamp, latency=latency)
