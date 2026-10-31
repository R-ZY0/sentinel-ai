"""Week 2 scenario definition regressions (no external packages required)."""
import copy
import json
import unittest
from pathlib import Path

from security.test_cases.validate_scenarios import ROOT, audit

MANIFEST = ROOT / "security/test_cases/week2_scenarios.json"

def fixture():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))

class Week2SecurityCaseTests(unittest.TestCase):
    def test_all_five_scenarios_and_mappings(self):
        self.assertEqual(audit(), [])

    def test_reject_duplicate_case_ids(self):
        data = fixture()
        data["test_cases"].append(copy.deepcopy(data["test_cases"][0]))
        self.assertTrue(any("Duplicate" in x for x in audit(manifest_override=data)))

    def test_reject_incorrect_owasp_mapping(self):
        data = fixture()
        data["test_cases"][0]["owasp_ids"] = ["LLM01:2025"]
        self.assertTrue(any("OWASP mapping mismatch" in x for x in audit(manifest_override=data)))

    def test_reject_missing_reference(self):
        data = fixture()
        data["test_cases"][1]["ground_truth_references"][0]["id"] = "MISSING"
        self.assertTrue(any("missing or ambiguous" in x for x in audit(manifest_override=data)))

    def test_attacker_echo_cannot_be_planted_as_fixture(self):
        data = fixture()
        data["test_cases"][1]["attack_prompt"] += " CANARY_SECRET_12345"
        self.assertTrue(any("attacker prompt contains" in x for x in audit(manifest_override=data)))

    def test_system_prompt_fixture_is_explicitly_missing(self):
        data = fixture()
        ref = data["test_cases"][0]["ground_truth_references"][0]
        self.assertEqual(ref["state"], "fixture_required")
        self.assertTrue(any("system prompt fixture must" in x for x in audit(
            manifest_override={**data,"test_cases":[{**data["test_cases"][0],
                "ground_truth_references":[{**ref,"state":"defined"}]}]+data["test_cases"][1:]}
        )))

    def test_no_cvss_score_without_assessment(self):
        data = fixture()
        data["test_cases"][3]["cvss_assessment_status"] = "assessed"
        self.assertTrue(any("CVSS cannot be pre-assessed" in x for x in audit(manifest_override=data)))

if __name__ == "__main__":
    unittest.main()
