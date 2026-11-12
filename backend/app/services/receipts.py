"""Persist the security team's attestation without changing its receipt contract."""
import hashlib
import hmac
import json
import os

from security_validation.src.adapter import from_backend_records
from security_validation.src.traceability import (
    validate_and_attest_backend_execution, verify_evidence_receipt,
)
from ..models import EvidenceReceipt


def audit_key():
    try:
        key = bytes.fromhex(os.environ.get("EVIDENCE_AUDIT_KEY", ""))
    except ValueError:
        raise ValueError("Evidence signing requires a server-managed hexadecimal key") from None
    if len(key) < 32:
        raise ValueError("Evidence signing requires at least 32 random bytes")
    return key


def key_id(key):
    return hashlib.sha256(key).hexdigest()[:24]


def backend_records(attempt, response):
    return ({"id": str(attempt.id), "scan_id": str(attempt.scan_id),
             "attack_case_id": attempt.attack_case_id, "payload": attempt.payload,
             "status": attempt.status},
            {"attack_attempt_id": str(response.attack_attempt_id), "content": response.content})


def attest(db, *, attempt, response, fixture, finding_id):
    key = audit_key()
    attempt_record, response_record = backend_records(attempt, response)
    result = validate_and_attest_backend_execution(
        attempt=attempt_record, response=response_record, test_case_id=attempt.test_case_id,
        trusted_fixture=fixture, finding_id=str(finding_id), audit_key=key,
    )
    attack, reply = from_backend_records(attempt_record, response_record, test_case_id=attempt.test_case_id)
    if not verify_evidence_receipt(result["evidence_receipt"], attack, reply,
            result["validation"], result["finding"], trusted_fixture=fixture, audit_key=key):
        raise ValueError("Evidence receipt verification failed")
    db.add(EvidenceReceipt(response_id=response.id, key_id=key_id(key), receipt=result["evidence_receipt"]))
    return result


def stored_receipt_integrity(stored, attempt, response, security_result):
    """Check the signed receipt body and retained DB records.

    The fixture digest is authenticated by the signature, but its raw preimage
    is deliberately not retained. This is integrity verification, not revalidation.
    """
    key = audit_key()
    if stored.key_id != key_id(key):
        return "key_unavailable"
    receipt = dict(stored.receipt)
    signature = receipt.pop("receipt_hmac_sha256", "")

    def mac(domain, value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        return hmac.new(key, domain.encode() + b"\x00" + data, hashlib.sha256).hexdigest()

    if not isinstance(signature, str) or not hmac.compare_digest(signature, mac("sentinel.receipt.v1", receipt)):
        return "invalid"
    first, second = backend_records(attempt, response)
    attack, reply = from_backend_records(first, second, test_case_id=attempt.test_case_id)
    for name, domain, value in [
        ("attack_run_hmac_sha256", "sentinel.attack_run.v1", attack),
        ("target_response_hmac_sha256", "sentinel.target_response.v1", reply),
        ("validation_hmac_sha256", "sentinel.validation.v1", security_result["validation"]),
        ("finding_hmac_sha256", "sentinel.finding.v1", security_result["finding"]),
    ]:
        if not hmac.compare_digest(receipt.get("digests", {}).get(name, ""), mac(domain, value)):
            return "invalid"
    return "verified"
