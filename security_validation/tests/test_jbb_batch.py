"""Tests for read-only 200-case JBB intake, captures, and review integrity."""
import copy
import hashlib
import json
import unittest
from pathlib import Path

from security_validation.src.jbb_batch import audit_jailbreakbench, load_jsonl

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "eval/dataset/processed/jailbreakbench_processed.jsonl"
STAMP = "2026-10-29T10:00:00+00:00"


def fixture(class_code="H"):
    name = "harmful" if class_code == "H" else "benign"
    return {"case_id": f"JBB-{class_code}-000", "source": "jailbreakbench",
            "source_index": "0", "behavior_class": name, "category": "jailbreak",
            "prompt": "A safe synthetic test prompt", "expected_behavior": "Safe answer",
            "ground_truth": "AMBIGUOUS",
            "reference_target": "This is not observed response evidence"}


def captured(case, *, response="I cannot comply.", error=None):
    return {"case_id": case["case_id"],
            "behavior_class": case["behavior_class"],
            "prompt_sha256": hashlib.sha256(case["prompt"].encode()).hexdigest(),
            "model": "synthetic-test-model", "target_mode": "protected",
            "captured_at_utc": STAMP, "response": response,
            "execution_error": error, "adjudicated_verdict": None}


def reviewed(case, response="I cannot comply.", outcome="safe_refusal"):
    return {"case_id": case["case_id"], "reviewer": "synthetic-reviewer",
            "reviewed_at_utc": STAMP, "rationale": "Human synthetic test review",
            "outcome": outcome,
            "response_sha256": hashlib.sha256(response.encode()).hexdigest()}


class JailbreakBenchBatchTests(unittest.TestCase):
    def test_real_dataset_has_200_unique_balanced_unadjudicated_cases(self):
        rows = load_jsonl(DATASET)
        report = audit_jailbreakbench(rows, require_full_dataset=True)
        self.assertEqual(report["dataset"]["cases"], 200)
        self.assertEqual(report["dataset"]["behavior_classes"], {"benign": 100, "harmful": 100})
        self.assertEqual(report["dataset"]["unadjudicated_ground_truth"], 200)
        self.assertEqual(report["captures"]["pending_capture"], 200)
        self.assertIsNone(report["metrics"]["response_level_attack_success_rate"])
        self.assertEqual(len(report["cases"]), 200)

    def test_full_dataset_matches_safe_expected_summary_snapshot(self):
        rows = load_jsonl(DATASET)
        observed = audit_jailbreakbench(rows, require_full_dataset=True)
        observed.pop("cases")
        expected_path = ROOT / "security_validation/examples/jbb_expected_summary.json"
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        self.assertEqual(observed, expected)

    def test_report_does_not_include_prompts_or_reference_targets(self):
        rows = [fixture()]
        report = audit_jailbreakbench(rows)
        rendered = json.dumps(report)
        self.assertNotIn(rows[0]["prompt"], rendered)
        self.assertNotIn(rows[0]["reference_target"], rendered)

    def test_duplicate_case_id_is_rejected(self):
        c = fixture()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit_jailbreakbench([c, copy.deepcopy(c)])

    def test_wrong_input_class_is_rejected(self):
        c = fixture()
        c["behavior_class"] = "benign"
        with self.assertRaisesRegex(ValueError, "behavior_class"):
            audit_jailbreakbench([c])

    def test_ground_truth_cannot_claim_safety_from_prompt_alone(self):
        c = fixture()
        c["ground_truth"] = "LEAK"
        with self.assertRaisesRegex(ValueError, "ground truth"):
            audit_jailbreakbench([c])

    def test_invalid_full_dataset_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly 200"):
            audit_jailbreakbench([fixture()], require_full_dataset=True)

    def test_duplicate_capture_is_rejected(self):
        c = fixture()
        record = captured(c)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit_jailbreakbench([c], [record, copy.deepcopy(record)])

    def test_unknown_capture_case_id_is_rejected(self):
        c = fixture()
        record = captured(c)
        record["case_id"] = "JBB-B-011"
        with self.assertRaisesRegex(ValueError, "not present"):
            audit_jailbreakbench([c], [record])

    def test_stale_capture_prompt_hash_is_rejected(self):
        c = fixture()
        record = captured(c)
        record["prompt_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            audit_jailbreakbench([c], [record])

    def test_capture_is_pending_human_review_not_leak(self):
        c = fixture()
        report = audit_jailbreakbench([c], [captured(c)])
        self.assertEqual(report["captures"]["captured"], 1)
        self.assertEqual(report["reviews"]["pending_review"], 1)
        self.assertIsNone(report["cases"][0]["reviewed_outcome"])
        self.assertNotIn("LEAK", json.dumps(report))

    def test_error_does_not_count_as_successful_capture(self):
        c = fixture()
        report = audit_jailbreakbench([c], [captured(c, response=None, error="timeout")])
        self.assertEqual(report["captures"]["execution_errors"], 1)
        self.assertEqual(report["captures"]["captured"], 0)
        self.assertEqual(report["reviews"]["not_reviewable"], 1)

    def test_empty_response_is_not_accepted_as_completed(self):
        c = fixture()
        report = audit_jailbreakbench([c], [captured(c, response="  ")])
        self.assertEqual(report["captures"]["empty_responses"], 1)
        self.assertEqual(report["reviews"]["reviewed"], 0)

    def test_unprotected_target_is_rejected(self):
        c = fixture()
        record = captured(c)
        record["target_mode"] = "unprotected"
        with self.assertRaisesRegex(ValueError, "protected"):
            audit_jailbreakbench([c], [record])

    def test_review_must_bind_to_exact_captured_response(self):
        c = fixture()
        record = captured(c)
        review = reviewed(c)
        report = audit_jailbreakbench([c], [record], [review])
        self.assertEqual(report["reviews"]["reviewed_outcomes"]["safe_refusal"], 1)
        tampered = copy.deepcopy(review)
        tampered["response_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "stale adjudication"):
            audit_jailbreakbench([c], [record], [tampered])

    def test_review_of_noncaptured_response_is_rejected(self):
        c = fixture()
        with self.assertRaisesRegex(ValueError, "cannot review"):
            audit_jailbreakbench([c], reviews=[reviewed(c)])

    def test_review_invalid_for_class_rejected(self):
        c = fixture("B")
        record = captured(c)
        review = reviewed(c, outcome="harmful_compliance")
        with self.assertRaisesRegex(ValueError, "invalid outcome"):
            audit_jailbreakbench([c], [record], [review])

    def test_unverified_inline_runner_label_ignored(self):
        c = fixture()
        record = captured(c)
        record["adjudicated_verdict"] = "LEAK"
        report = audit_jailbreakbench([c], [record])
        self.assertEqual(report["reviews"]["reviewed"], 0)
        self.assertIsNone(report["metrics"]["accuracy"])

    def test_multiple_models_cannot_be_combined(self):
        a,b = fixture("H"), fixture("B")
        other = captured(b)
        other["model"] = "different-model"
        with self.assertRaisesRegex(ValueError, "multiple models"):
            audit_jailbreakbench([a,b], [captured(a), other])

    def test_no_raw_response_in_report(self):
        c = fixture()
        record = captured(c, response="Unique response text not to be disclosed")
        report = audit_jailbreakbench([c], [record])
        self.assertNotIn(record["response"], json.dumps(report))


if __name__ == "__main__":
    unittest.main()
