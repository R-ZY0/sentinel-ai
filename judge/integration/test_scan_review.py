"""Dependency-free regression tests for scan-specific, immutable Judge evidence."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from judge.integration.review_completed_scan import (
    digest, review_paths, validate_capture, validate_advisories, summary,
    evaluate_saved_responses,
)


class JudgeScanReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scan_id = uuid4()
        self.capture, self.output = review_paths(self.scan_id, self.temp.name)
        self.capture.parent.mkdir(parents=True)
        self.rows = [
            {
                "scan_id": str(self.scan_id),
                "case_id": f"CASE-{i:03d}",
                "prompt": f"Synthetic test {i}",
                "expected_behavior": "Protect the planted canary",
                "response": f"Test answer {i}",
                "response_sha256": digest(f"Test answer {i}"),
                "historical_finding_status": [],
            }
            for i in range(15)
        ]
        self.write_rows(self.capture, self.rows)

    @staticmethod
    def write_rows(path, rows):
        path.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")

    def make_advisory(self, row, verdict="NO_LEAK"):
        return {
            "scan_id": str(self.scan_id),
            "case_id": row["case_id"],
            "response_sha256": row["response_sha256"],
            "judge_model": "llama3.2:3b",
            "advisory_only": True,
            "hybrid": {"verdict": verdict},
        }

    def test_validates_15_independent_responses(self):
        actual = validate_capture(self.capture, self.scan_id)
        self.assertEqual(len(actual), 15)

    def test_rejects_wrong_hash(self):
        self.rows[0]["response_sha256"] = "0" * 64
        self.write_rows(self.capture, self.rows)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_capture(self.capture, self.scan_id)

    def test_rejects_duplicate_case(self):
        self.rows[1]["case_id"] = self.rows[0]["case_id"]
        self.write_rows(self.capture, self.rows)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_capture(self.capture, self.scan_id)

    def test_rejects_wrong_scan_id(self):
        self.rows[0]["scan_id"] = str(uuid4())
        self.write_rows(self.capture, self.rows)
        with self.assertRaisesRegex(ValueError, "different scan"):
            validate_capture(self.capture, self.scan_id)

    def test_scans_are_isolated_directories(self):
        x, y = review_paths(uuid4(), self.temp.name)
        self.assertNotEqual(self.capture.parent, x.parent)
        self.assertNotEqual(self.output, y)

    def test_rejects_duplicate_or_tampered_advisory(self):
        record = self.make_advisory(self.rows[0])
        self.write_rows(self.output, [record, record])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_advisories(self.output, self.rows, self.scan_id)
        record["response_sha256"] = "incorrect"
        self.write_rows(self.output, [record])
        with self.assertRaisesRegex(ValueError, "mismatch"):
            validate_advisories(self.output, self.rows, self.scan_id)

    def test_no_forged_security_verdict(self):
        rec = self.make_advisory(self.rows[0])
        rec["advisory_only"] = False
        self.write_rows(self.output, [rec])
        with self.assertRaisesRegex(ValueError, "advisory-only"):
            validate_advisories(self.output, self.rows, self.scan_id)

    def test_resume_completed_evidence_without_loading_models(self):
        self.write_rows(self.output, [self.make_advisory(r) for r in self.rows])
        # No judge modules or model calls should be required for idempotent resume.
        evaluate_saved_responses(self.scan_id, self.capture, self.output,
                                 "llama3.2:3b", "http://127.0.0.1:11434")
        self.assertEqual(len(validate_advisories(self.output, self.rows, self.scan_id)), 15)

    def test_summary_does_not_claim_jailbreak_success(self):
        self.write_rows(self.output, [self.make_advisory(r) for r in self.rows])
        from contextlib import redirect_stdout
        import io
        capture = io.StringIO()
        with redirect_stdout(capture):
            summary(self.scan_id, self.capture, self.output)
        self.assertIn("NOT_A_JAILBREAK_OR_PROMPT_INJECTION_VERDICT: True", capture.getvalue())
        self.assertIn("JUDGE_ON_PERSISTED_BACKEND_EVIDENCE: PASS", capture.getvalue())

    def test_bad_model_cannot_resume(self):
        self.write_rows(self.output, [self.make_advisory(self.rows[0])])
        with self.assertRaisesRegex(ValueError, "different judge model"):
            validate_advisories(self.output, self.rows, self.scan_id, model="other:latest")


if __name__ == "__main__":
    unittest.main()
