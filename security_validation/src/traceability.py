"""HMAC-protected evidence receipts for component-level audit traceability.

Integrity checks are useful only when audit_key and trusted fixtures originate
from an authorized server-side service. A receipt does not prove a target was
authorized, a flag was truthful, or a vulnerability was exploited.
No external services, files, or database writes are performed.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re

from .adapter import from_backend_records
from .pipeline import validate_backend_execution

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERDICTS = {"LEAK", "NO_LEAK", "AMBIGUOUS"}
_STATUSES = {"confirmed", "rejected", "potential"}


def _key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("audit_key must be at least 32 secret random bytes")
    return key


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hmac(key: bytes, domain: str, value: object) -> str:
    # Context separation avoids cross-protocol reuse of a valid MAC.
    return hmac.new(
        key, domain.encode("ascii") + b"\x00" + _canonical(value), hashlib.sha256
    ).hexdigest()


def _id(source: dict, name: str) -> str:
    value = source.get(name)
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise ValueError(f"Unsafe or missing identifier: {name}")
    return value


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(value, str):
        raise ValueError("recorded_at must be a timezone-aware ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid recorded_at timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("recorded_at must have a timezone offset")
    return value


def build_evidence_receipt(
    attack_run: dict, target_response: dict, validation: dict, finding: dict,
    *, trusted_fixture: dict, audit_key: bytes, recorded_at: str | None = None,
) -> dict:
    """Bind validation+finding to exact input bytes without storing raw payloads.

    The MACs cover complete canonical records (including fixture values and
    authorization flags), but the receipt exposes only safe IDs and status.
    This does not authenticate the truthfulness of caller-provided assertions.
    """
    key = _key(audit_key)
    if not all(isinstance(x, dict) for x in
               (attack_run, target_response, validation, finding, trusted_fixture)):
        raise TypeError("All record arguments must be dictionaries")
    ids = {
        "scan_id": _id(attack_run, "scan_id"),
        "attack_id": _id(attack_run, "attack_id"),
        "attempt_id": _id(attack_run, "attempt_id"),
        "test_case_id": _id(attack_run, "test_case_id"),
        "finding_id": _id(finding, "finding_id"),
    }
    if (finding.get("scan_id") != ids["scan_id"]
            or finding.get("test_case_id") != ids["test_case_id"]
            or validation.get("test_case_id") != ids["test_case_id"]
            or target_response.get("attack_id") != ids["attack_id"]
            or (target_response.get("attempt_id") is not None
                and str(target_response["attempt_id"]) != ids["attempt_id"])
            or trusted_fixture.get("test_case_id") != ids["test_case_id"]):
        raise ValueError("Source identifiers do not agree")
    verdict = validation.get("verdict")
    status = validation.get("validation_status")
    if verdict not in _VERDICTS or status not in _STATUSES:
        raise ValueError("Unrecognized validation verdict or status")
    expected_status = {
        "LEAK": "confirmed", "NO_LEAK": "rejected", "AMBIGUOUS": "potential"
    }[verdict]
    if (status != expected_status or finding.get("status") != status
            or finding.get("evidence") != validation.get("evidence")
            or finding.get("category") != validation.get("category")):
        raise ValueError("Finding and validation are inconsistent")
    content = target_response.get("response")
    body = {
        "receipt_version": "1.0",
        "recorded_at": _timestamp(recorded_at),
        "identifiers": ids,
        "verdict": verdict,
        "finding_status": status,
        "response_present": isinstance(content, str) and bool(content.strip()),
        "digests": {
            "attack_run_hmac_sha256": _hmac(key, "sentinel.attack_run.v1", attack_run),
            "target_response_hmac_sha256": _hmac(key, "sentinel.target_response.v1", target_response),
            "trusted_fixture_hmac_sha256": _hmac(key, "sentinel.trusted_fixture.v1", trusted_fixture),
            "validation_hmac_sha256": _hmac(key, "sentinel.validation.v1", validation),
            "finding_hmac_sha256": _hmac(key, "sentinel.finding.v1", finding),
        },
    }
    return {**body, "receipt_hmac_sha256": _hmac(key, "sentinel.receipt.v1", body)}


def verify_evidence_receipt(
    receipt: dict, attack_run: dict, target_response: dict,
    validation: dict, finding: dict, *, trusted_fixture: dict,
    audit_key: bytes,
) -> bool:
    """Check binding and tamper detection; does not independently establish truth."""
    if not isinstance(receipt, dict):
        return False
    recorded_at = receipt.get("recorded_at")
    try:
        expected = build_evidence_receipt(
            attack_run, target_response, validation, finding,
            trusted_fixture=trusted_fixture, audit_key=audit_key,
            recorded_at=recorded_at,
        )
        actual_mac = receipt.get("receipt_hmac_sha256")
        return (
            isinstance(actual_mac, str)
            and hmac.compare_digest(actual_mac, expected["receipt_hmac_sha256"])
            and receipt == expected
        )
    except (TypeError, ValueError, KeyError):
        return False


def validate_and_attest_backend_execution(
    *, attempt: dict, response: dict | None, test_case_id: str,
    trusted_fixture: dict, finding_id: str, audit_key: bytes,
    recorded_at: str | None = None,
) -> dict:
    """Run the existing read-only validation and attach an authenticated receipt."""
    result = validate_backend_execution(
        attempt=attempt, response=response, test_case_id=test_case_id,
        trusted_fixture=trusted_fixture, finding_id=finding_id,
    )
    attack_run, target_response = from_backend_records(
        attempt, response, test_case_id=test_case_id,
    )
    receipt = build_evidence_receipt(
        attack_run, target_response, result["validation"], result["finding"],
        trusted_fixture=trusted_fixture, audit_key=audit_key, recorded_at=recorded_at,
    )
    return {**result, "evidence_receipt": receipt}
