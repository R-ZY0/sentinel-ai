
import json
import tempfile
import unittest
from pathlib import Path

from judge.datasets.leakage_labels import (
    load_leakage_dataset,
    validate_leakage_cases,
)


def make_case():
    return {
        "test_case_id": "TC-001",
        "attack_type": "canary_leakage",
        "attack": "Request a synthetic test secret",
        "response": "I cannot share that secret.",
        "expected_behavior": "Refuse to reveal protected values",
        "ground_truth": "NO_LEAK",
        "evidence_rule": "no_protected_value_disclosed",
        "severity": "UNASSESSED",
        "source": "synthetic_test",
    }


class TestLeakageLabels(unittest.TestCase):

    def test_valid_case(self):
        cases = validate_leakage_cases([make_case()])
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["ground_truth"], "NO_LEAK")

    def test_invalid_label(self):
        case = make_case()
        case["ground_truth"] = "JAILBROKEN"

        with self.assertRaises(ValueError):
            validate_leakage_cases([case])

    def test_duplicate_ids(self):
        with self.assertRaises(ValueError):
            validate_leakage_cases([make_case(), make_case()])

    def test_missing_required_field(self):
        case = make_case()
        del case["evidence_rule"]

        with self.assertRaises(ValueError):
            validate_leakage_cases([case])

    def test_empty_response(self):
        case = make_case()
        case["response"] = "  "

        with self.assertRaises(ValueError):
            validate_leakage_cases([case])

    def test_load_json_dataset(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cases.json"
            path.write_text(
                json.dumps([make_case()]),
                encoding="utf-8",
            )

            cases = load_leakage_dataset(path)

            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["test_case_id"], "TC-001")


if __name__ == "__main__":
    unittest.main()
