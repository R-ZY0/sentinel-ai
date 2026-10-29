"""Offline contract tests for Week 2 synthetic evaluation reporting."""
import json
from pathlib import Path
import unittest

from judge.eval.run_week2_baselines import evaluate_cases, CASES_PATH
from judge.verdict import JudgeVerdict, Verdict


class FakeRunner:
    def evaluate(self, target_response):
        expected = target_response["response"]
        verdict = Verdict.LEAK if "CANARY_SECRET_12345" in expected else Verdict.NO_LEAK
        result = JudgeVerdict(verdict, 0.8, "synthetic test double", {})
        return {
            "attack_id": target_response["attack_id"],
            "advisory_only": True,
            "baselines": {name: result.to_dict() for name in ("B0", "B1", "B2", "B3")},
        }


class Week2EvaluationTests(unittest.TestCase):
    def test_report_shape_for_existing_fixtures(self):
        cases = json.loads(Path(CASES_PATH).read_text(encoding="utf-8"))
        report = evaluate_cases(cases, FakeRunner())
        self.assertTrue(report["advisory_only"])
        self.assertEqual(len(report["cases"]), len(cases))
        self.assertEqual(set(report["summary"]), {"B0", "B1", "B2", "B3"})
        for row in report["cases"]:
            self.assertTrue(row["advisory_only"])
            self.assertEqual(set(row["baselines"]), {"B0", "B1", "B2", "B3"})
            for name in ("B0", "B1", "B2", "B3"):
                self.assertIn("confidence", row["baselines"][name])
                self.assertIn("reason", row["baselines"][name])
                self.assertIn("signals", row["baselines"][name])

    def test_duplicate_case_id_rejected(self):
        case = {"id": "x", "attack": "a", "response": "r", "expected_behavior": "b", "expected_verdict": "NO_LEAK"}
        with self.assertRaisesRegex(ValueError, "unique"):
            evaluate_cases([case, dict(case)], FakeRunner())

    def test_invalid_expected_verdict_rejected(self):
        case = {"id": "x", "attack": "a", "response": "r", "expected_behavior": "b", "expected_verdict": "SAFE"}
        with self.assertRaisesRegex(ValueError, "expected verdict"):
            evaluate_cases([case], FakeRunner())

    def test_empty_cases_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty"):
            evaluate_cases([], FakeRunner())


if __name__ == "__main__":
    unittest.main()
