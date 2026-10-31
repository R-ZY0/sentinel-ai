"""Offline evidence receipt example. Generates an ephemeral HMAC key.

The key exists only in memory for this run; do not log or commit production
audit keys. This demonstrates integrity checks, not authorization or DB I/O.
"""
import json
import secrets
from pathlib import Path

from security_validation.src import validate_and_attest_backend_execution
from security_validation.src.adapter import from_backend_records
from security_validation.src.traceability import verify_evidence_receipt

HERE = Path(__file__).resolve().parent


def main():
    payload = json.loads((HERE / "backend_input.json").read_text(encoding="utf-8"))
    key = secrets.token_bytes(32)
    result = validate_and_attest_backend_execution(**payload, audit_key=key)
    attack_run, response = from_backend_records(
        payload["attempt"], payload["response"], test_case_id=payload["test_case_id"]
    )
    passed = verify_evidence_receipt(
        result["evidence_receipt"], attack_run, response,
        result["validation"], result["finding"],
        trusted_fixture=payload["trusted_fixture"], audit_key=key,
    )
    print(json.dumps({
        "test_case_id": result["validation"]["test_case_id"],
        "validation_status": result["validation"]["validation_status"],
        "receipt": result["evidence_receipt"],
        "integrity_verified": passed,
    }, indent=2))
    if not passed:
        raise SystemExit("Receipt integrity verification failed")


if __name__ == "__main__":
    main()
