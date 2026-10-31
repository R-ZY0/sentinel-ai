"""Integrity, privacy and traceability tests with synthetic offline records."""
import copy
import json
import unittest
from pathlib import Path

from security_validation.src import validate_and_attest_backend_execution
from security_validation.src.adapter import from_backend_records
from security_validation.src.traceability import verify_evidence_receipt

HERE = Path(__file__).resolve().parents[1] / "examples"
EXAMPLE = json.loads((HERE / "backend_input.json").read_text(encoding="utf-8"))
KEY = b"local-test-only-hmac-key-not-for-production-01"
OTHER_KEY = b"another-local-test-only-secret-value-02"
TIME = "2026-10-29T10:30:00+00:00"


def case():
    return copy.deepcopy(EXAMPLE)


def attest(record, *, audit_key=KEY):
    return validate_and_attest_backend_execution(
        **record, audit_key=audit_key, recorded_at=TIME,
    )


def check(receipt, record, result, *, audit_key=KEY):
    attack_run, response = from_backend_records(
        record["attempt"], record["response"], test_case_id=record["test_case_id"]
    )
    return verify_evidence_receipt(
        receipt, attack_run, response, result["validation"], result["finding"],
        trusted_fixture=record["trusted_fixture"], audit_key=audit_key,
    )


class EvidenceTraceabilityTests(unittest.TestCase):
    def test_confirmed_finding_receipt_verifies(self):
        record = case()
        result = attest(record)
        self.assertTrue(check(result["evidence_receipt"], record, result))
        self.assertEqual(result["evidence_receipt"]["finding_status"], "confirmed")

    def test_receipt_does_not_reveal_prompt_response_or_fixture_value(self):
        record = case()
        result = attest(record)
        serial = json.dumps(result["evidence_receipt"])
        self.assertNotIn("CANARY_SECRET_12345", serial)
        self.assertNotIn(record["attempt"]["payload"], serial)
        self.assertNotIn(record["response"]["content"], serial)
        self.assertEqual(len(result["evidence_receipt"]["receipt_hmac_sha256"]), 64)

    def test_changed_response_fails_verification(self):
        record = case()
        result = attest(record)
        tampered = copy.deepcopy(record)
        tampered["response"]["content"] += " edited"
        self.assertFalse(check(result["evidence_receipt"], tampered, result))

    def test_changed_attack_payload_fails_verification(self):
        record = case()
        result = attest(record)
        tampered = copy.deepcopy(record)
        tampered["attempt"]["payload"] += " modified"
        self.assertFalse(check(result["evidence_receipt"], tampered, result))

    def test_changed_fixture_fails_verification(self):
        record = case()
        result = attest(record)
        tampered = copy.deepcopy(record)
        tampered["trusted_fixture"]["values"][0]["value"] = "DIFFERENT_CANARY_456"
        self.assertFalse(check(result["evidence_receipt"], tampered, result))

    def test_changed_finding_fails_verification(self):
        record = case()
        result = attest(record)
        changed = copy.deepcopy(result)
        changed["finding"]["confidence"] = 0.1
        self.assertFalse(check(result["evidence_receipt"], record, changed))

    def test_modified_receipt_is_rejected(self):
        record = case()
        result = attest(record)
        changed = copy.deepcopy(result["evidence_receipt"])
        changed["finding_status"] = "rejected"
        self.assertFalse(check(changed, record, result))

    def test_wrong_audit_key_rejected(self):
        record = case()
        result = attest(record)
        self.assertFalse(check(result["evidence_receipt"], record, result, audit_key=OTHER_KEY))

    def test_weak_key_is_rejected(self):
        with self.assertRaises(ValueError):
            attest(case(), audit_key=b"too-short")

    def test_failed_execution_has_potential_receipt(self):
        record = case()
        record["attempt"]["status"] = "failed"
        record["response"] = None
        result = attest(record)
        self.assertEqual(result["evidence_receipt"]["finding_status"], "potential")
        self.assertFalse(result["evidence_receipt"]["response_present"])
        self.assertTrue(check(result["evidence_receipt"], record, result))

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_and_attest_backend_execution(
                **case(), audit_key=KEY, recorded_at="2026-10-29T10:30:00"
            )

    def test_unauthorized_target_is_still_blocked(self):
        record = case()
        record["trusted_fixture"]["target_authorized"] = False
        with self.assertRaises(PermissionError):
            attest(record)


if __name__ == "__main__":
    unittest.main()
