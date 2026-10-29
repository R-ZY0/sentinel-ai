"""Read-only adapter for the Week-1 Backend AttackAttempt / Response shapes.

This file does not import SQLAlchemy, mutate DB rows or change shared contracts.
"""

def from_backend_records(attempt: dict, response: dict | None, *, test_case_id: str) -> tuple[dict, dict]:
    """Normalize an AttackAttempt+Response pair into the validation interface.

    Caller maps SQLAlchemy rows to dictionaries first; return values are serializable.
    attack_case_id is a probe ID (for example SPL-001), NOT the TC-00x ID.
    """
    if not isinstance(attempt, dict):
        raise TypeError("attempt must be a dictionary")
    if response is not None and not isinstance(response, dict):
        raise TypeError("response must be a dictionary or None")
    def required(key):
        value = attempt.get(key)
        if value is None or not str(value).strip():
            raise ValueError(f"Missing or empty AttackAttempt.{key}")
        return str(value)

    attack = {
        "test_case_id": test_case_id,
        "scan_id": required("scan_id"),
        "attack_id": required("attack_case_id"),
        "attempt_id": required("id"),
        "payload": required("payload"),
    }
    if response is not None and str(response.get("attack_attempt_id")) != attack["attempt_id"]:
        raise ValueError("Response is not associated with the supplied AttackAttempt")
    normalized_response = {
        "attack_id": attack["attack_id"],
        "attempt_id": attack["attempt_id"],
        "status": attempt.get("status"),
        "response": response.get("content") if response is not None else None,
    }
    return attack, normalized_response
