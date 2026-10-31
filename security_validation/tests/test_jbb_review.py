"""Offline human review workflow; no raw corpus contents in test output."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from security_validation.src.jbb_batch import audit_jailbreakbench, load_jsonl
from security_validation.src.jbb_review import (
    make_human_review, pending_review_queue, private_review_materials,
    save_private_human_review,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-10-29T08:30:00+00:00"


def case(prefix):
    return {
        "case_id": f"JBB-{prefix}-000",
        "source": "jailbreakbench",
        "source_index": "0",
        "category": "jailbreak",
        "behavior_class": "harmful" if prefix == "H" else "benign",
        "prompt": "A synthetic review prompt for tests only",
        "expected_behavior": "Respond safely to the input",
        "ground_truth": "AMBIGUOUS",
        "reference_target": "Not an actual observed response",
    }


def capture(c, response="No, I cannot provide that."):
    import hashlib
    return {
        "case_id": c["case_id"],
        "behavior_class": c["behavior_class"],
        "prompt_sha256": hashlib.sha256(c["prompt"].encode("utf-8")).hexdigest(),
        "model": "synthetic-review-model",
        "target_mode": "protected",
        "captured_at_utc": NOW,
        "response": response,
        "execution_error": None,
        "adjudicated_verdict": None,
    }


def review(cases, captures, existing=None, **kwargs):
    return make_human_review(
        cases, captures, existing or [],
        case_id=kwargs.get("case_id", cases[0]["case_id"]),
        reviewer=kwargs.get("reviewer", "human-reviewer-01"),
        outcome=kwargs.get("outcome", "safe_refusal"),
        rationale=kwargs.get("rationale", "Synthetic manual refusal assessment"),
        reviewed_at_utc=kwargs.get("reviewed_at_utc", NOW),
    )


class JailbreakBenchHumanReviewTests(unittest.TestCase):
    def setUp(self):
        self.h = case("H")
        self.b = case("B")
        self.cases = [self.h, self.b]
        self.captures = [capture(self.h), capture(self.b)]

    def test_queue_has_only_ids_and_balanced_classes(self):
        q = pending_review_queue(self.cases, self.captures)
        self.assertEqual(q["remaining"], 2)
        self.assertEqual([x["case_id"] for x in q["next_cases"]],
                         ["JBB-H-000", "JBB-B-000"])
        self.assertNotIn(self.h["prompt"], json.dumps(q))
        self.assertNotIn(self.captures[0]["response"], json.dumps(q))

    def test_queue_excludes_completed_review(self):
        r = review(self.cases, self.captures)
        q = pending_review_queue(self.cases, self.captures, [r])
        self.assertEqual(q["remaining"], 1)
        self.assertEqual(q["next_cases"][0]["case_id"], "JBB-B-000")

    def test_queue_rejects_invalid_limit(self):
        with self.assertRaises(ValueError):
            pending_review_queue(self.cases, self.captures, limit=0)

    def test_private_materials_only_for_selected_capture(self):
        m = private_review_materials(self.cases, self.captures, [],
                                     case_id="JBB-B-000")
        self.assertEqual(m["response"], self.captures[1]["response"])
        self.assertEqual(m["allowed_outcomes"], ["appropriate_help", "inconclusive", "over_refusal"])

    def test_private_materials_disallow_unknown_case(self):
        with self.assertRaises(ValueError):
            private_review_materials(self.cases, self.captures, [],
                                     case_id="JBB-H-077")

    def test_cannot_review_nonexecuted_case(self):
        with self.assertRaises(ValueError):
            review(self.cases, self.captures[1:])

    def test_review_needs_explicit_human_reason(self):
        with self.assertRaises(ValueError):
            review(self.cases, self.captures, rationale="")
        with self.assertRaises(ValueError):
            review(self.cases, self.captures, reviewer=" ")

    def test_review_bindings_sha_and_timestamp(self):
        r = review(self.cases, self.captures)
        self.assertEqual(len(r["response_sha256"]), 64)
        self.assertEqual(r["reviewed_at_utc"], NOW)
        report = audit_jailbreakbench(self.cases, self.captures, [r])
        self.assertEqual(report["reviews"]["reviewed"], 1)

    def test_invalid_class_outcome_not_recorded(self):
        with self.assertRaises(ValueError):
            review(self.cases, self.captures, outcome="appropriate_help")

    def test_duplicate_review_not_recorded(self):
        r = review(self.cases, self.captures)
        with self.assertRaises(ValueError):
            review(self.cases, self.captures, existing=[r])

    def test_stale_response_fingerprint_fails_audit(self):
        r = review(self.cases, self.captures)
        changed = copy.deepcopy(self.captures)
        changed[0]["response"] = "Different captured text"
        with self.assertRaisesRegex(ValueError, "stale adjudication"):
            audit_jailbreakbench(self.cases, changed, [r])

    def test_naive_timestamp_not_allowed(self):
        with self.assertRaises(ValueError):
            review(self.cases, self.captures, reviewed_at_utc="2026-10-29T08:30:00")

    def test_raw_reply_should_not_be_copied_into_rationale(self):
        with self.assertRaises(ValueError):
            review(self.cases, self.captures, rationale="Because " + self.captures[0]["response"])

    def test_private_file_is_atomic_and_persists_one_review(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "human_reviews.jsonl"
            saved = save_private_human_review(
                path, self.cases, self.captures,
                case_id="JBB-H-000", reviewer="human-reviewer-01",
                outcome="safe_refusal", rationale="Safe synthetic refusal was observed",
                reviewed_at_utc=NOW,
            )
            stored = load_jsonl(path)
            self.assertEqual(stored, [saved])
            self.assertFalse(path.with_name(path.name + ".lock").exists())

    def test_duplicate_private_file_review_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "human_reviews.jsonl"
            args = dict(
                case_id="JBB-H-000", reviewer="human-reviewer-01",
                outcome="safe_refusal", rationale="Synthetic manual refusal assessment",
                reviewed_at_utc=NOW,
            )
            save_private_human_review(path, self.cases, self.captures, **args)
            first = path.read_text(encoding="utf-8")
            with self.assertRaises(ValueError):
                save_private_human_review(path, self.cases, self.captures, **args)
            self.assertEqual(path.read_text(encoding="utf-8"), first)

    def test_in_repo_review_file_is_blocked(self):
        path = ROOT / "security_validation" / "forbidden_reviews.jsonl"
        with self.assertRaisesRegex(ValueError, "outside the repository"):
            save_private_human_review(
                path, self.cases, self.captures,
                case_id="JBB-H-000", reviewer="human-reviewer-01",
                outcome="safe_refusal", rationale="Synthetic manual refusal assessment",
            )

    def test_existing_lock_blocks_second_writer(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "human_reviews.jsonl"
            lock = path.with_name(path.name + ".lock")
            lock.write_text("locked", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                save_private_human_review(
                    path, self.cases, self.captures,
                    case_id="JBB-H-000", reviewer="human-reviewer-01",
                    outcome="safe_refusal", rationale="Synthetic manual refusal assessment",
                )
            self.assertTrue(lock.exists())


if __name__ == "__main__":
    unittest.main()
