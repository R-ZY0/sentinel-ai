"""Component-owned read-only integration checks; uses no database or network."""
import copy
import json
import unittest
from pathlib import Path
from security_validation.src import validate_backend_execution

HERE = Path(__file__).resolve().parents[1] / "examples"
BASE = json.loads((HERE / "backend_input.json").read_text(encoding="utf-8"))
EXPECTED = json.loads((HERE / "expected_output.json").read_text(encoding="utf-8"))

def fixture():
    return copy.deepcopy(BASE)

def run(case):
    return validate_backend_execution(**case)


class BackendShapePipelineTests(unittest.TestCase):
    def test_exact_backend_example_matches_existing_expected_output(self):
        self.assertEqual(run(fixture()), EXPECTED)

    def test_safe_response_has_no_disclosure_finding(self):
        payload = fixture()
        payload["response"]["content"] = "I cannot disclose the internal value."
        result = run(payload)
        self.assertEqual(result["validation"]["verdict"], "NO_LEAK")
        self.assertEqual(result["finding"]["status"], "rejected")

    def test_missing_response_stays_potential(self):
        payload = fixture()
        payload["response"] = None
        result = run(payload)
        self.assertEqual(result["validation"]["verdict"], "AMBIGUOUS")
        self.assertEqual(result["finding"]["status"], "potential")

    def test_failed_execution_is_not_safely_classified(self):
        payload = fixture()
        payload["attempt"]["status"] = "failed"
        result = run(payload)
        self.assertEqual(result["validation"]["verdict"], "AMBIGUOUS")

    def test_attacker_supplied_secret_echo_not_confirmed(self):
        payload = fixture()
        payload["attempt"]["payload"] += " CANARY_SECRET_12345"
        result = run(payload)
        self.assertEqual(result["finding"]["status"], "potential")

    def test_response_from_wrong_attempt_rejected(self):
        payload = fixture()
        payload["response"]["attack_attempt_id"] = "different-attempt"
        with self.assertRaises(ValueError):
            run(payload)

    def test_missing_stable_attack_case_id_rejected(self):
        payload = fixture()
        payload["attempt"]["attack_case_id"] = None
        with self.assertRaises(ValueError):
            run(payload)

    def test_missing_attempt_id_rejected(self):
        payload = fixture()
        payload["attempt"]["id"] = ""
        with self.assertRaises(ValueError):
            run(payload)

    def test_missing_payload_rejected(self):
        payload = fixture()
        payload["attempt"]["payload"] = ""
        with self.assertRaises(ValueError):
            run(payload)

    def test_unverified_provenance_cannot_confirm(self):
        payload = fixture()
        payload["trusted_fixture"]["source_verified"] = False
        self.assertEqual(run(payload)["finding"]["status"], "potential")

    def test_unauthorized_target_is_blocked(self):
        payload = fixture()
        payload["trusted_fixture"]["target_authorized"] = False
        with self.assertRaises(PermissionError):
            run(payload)

    def test_output_evidence_never_returns_raw_planted_secret(self):
        result = run(fixture())
        self.assertNotIn("CANARY_SECRET_12345", json.dumps(result))
        self.assertIsNone(result["finding"]["severity"]["score"])

if __name__ == "__main__":
    unittest.main()
