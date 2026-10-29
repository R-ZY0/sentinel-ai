"""Conservative CTI references and CVSS readiness checks, no network/DB."""
import copy
import json
import unittest
from pathlib import Path

from jsonschema.exceptions import ValidationError

from security_validation.src import validate_backend_execution
from security_validation.src.triage import triage_finding

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/backend_input.json"
BASE = json.loads(EXAMPLE.read_text(encoding="utf-8"))


def finding(status="confirmed"):
    p = copy.deepcopy(BASE)
    if status == "potential":
        p["response"] = None
    elif status == "rejected":
        p["response"]["content"] = "I cannot reveal a private internal value."
    return validate_backend_execution(**p)["finding"]


class CtiSeverityTriageTests(unittest.TestCase):
    def test_confirmed_requires_manual_impact_and_cvss_review(self):
        result = triage_finding(finding())
        self.assertEqual(result["disposition"], "requires_impact_and_cvss_review")
        self.assertTrue(result["severity_readiness"]["review_required"])
        self.assertEqual(result["severity_readiness"]["cvss_version"], "4.0")
        self.assertIsNone(result["severity_readiness"]["score"])

    def test_exact_canonical_taxonomy_refs_loaded(self):
        result = triage_finding(finding())["cti_context"]
        self.assertEqual(result["owasp"][0]["id"], "LLM02:2025")
        self.assertEqual(result["cwe"][0]["id"], "CWE-200")
        self.assertTrue(all(url.startswith("https://") for url in result["source_urls"]))

    def test_no_external_intelligence_or_attack_attribution_fabricated(self):
        result = triage_finding(finding())["cti_context"]
        self.assertFalse(result["external_feed_connected"])
        self.assertFalse(result["threat_actor_attributed"])
        self.assertFalse(result["campaign_attributed"])
        self.assertEqual(result["indicator_observations"], [])

    def test_potential_stays_unassessed(self):
        result = triage_finding(finding("potential"))
        self.assertEqual(result["disposition"], "requires_evidence_review")
        self.assertFalse(result["severity_readiness"]["review_required"])
        self.assertIsNone(result["severity_readiness"]["vector"])

    def test_rejected_is_not_scored_as_vulnerability(self):
        result = triage_finding(finding("rejected"))
        self.assertEqual(result["disposition"], "no_confirmed_disclosure")
        self.assertIsNone(result["severity_readiness"]["rating"])

    def test_unreviewed_cvss_score_is_rejected(self):
        f = finding()
        f["severity"]["score"] = 9.8
        with self.assertRaises(ValueError):
            triage_finding(f)

    def test_unreviewed_cvss_vector_is_rejected(self):
        f = finding()
        f["severity"]["vector"] = "CVSS:4.0/AV:N"
        with self.assertRaises(ValueError):
            triage_finding(f)

    def test_taxonomy_tampering_is_rejected(self):
        f = finding()
        f["classification"]["cwe"][0]["id"] = "CWE-999"
        with self.assertRaises(ValueError):
            triage_finding(f)

    def test_confirmed_requires_validated_leakage(self):
        f = finding()
        f["evidence"][0]["validated"] = False
        with self.assertRaises(ValueError):
            triage_finding(f)

    def test_invalid_shared_finding_schema_rejected(self):
        f = finding()
        f["unexpected"] = "field"
        with self.assertRaises(ValidationError):
            triage_finding(f)

    def test_does_not_change_original_finding(self):
        f = finding()
        before = copy.deepcopy(f)
        triage_finding(f)
        self.assertEqual(f, before)

    def test_no_raw_planted_canary_in_enrichment(self):
        result = triage_finding(finding())
        self.assertNotIn("CANARY_SECRET_12345", json.dumps(result))

    def test_invalid_finding_rejected(self):
        with self.assertRaises(TypeError):
            triage_finding("invalid")


if __name__ == "__main__":
    unittest.main()
