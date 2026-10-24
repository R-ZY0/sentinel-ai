"""Dataset contract tests. No Ollama, networking or third-party packages required."""
import csv
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from eval.dataset.process_jailbreakbench import load_cases, process_dataset


class JailbreakBenchDatasetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raw = Path(self.tmp.name) / "raw"
        self.raw.mkdir()

    def write_split(self, split, rows):
        with (self.raw / f"{split}-behaviors.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Index", "Behavior", "Goal", "Target"])
            writer.writeheader()
            writer.writerows(rows)

    def fixture(self):
        self.write_split("harmful", [{"Index": "0", "Behavior": "harmful_test", "Goal": "harmful question", "Target": "unsafe completion"}])
        self.write_split("benign", [{"Index": "0", "Behavior": "benign_test", "Goal": "benign question", "Target": "helpful completion"}])

    def test_split_ids_are_unique_even_with_equal_source_indices(self):
        self.fixture()
        rows = load_cases(self.raw)
        self.assertEqual([r["case_id"] for r in rows], ["JBB-H-000", "JBB-B-000"])
        self.assertEqual(len(set(r["case_id"] for r in rows)), 2)

    def test_input_class_is_not_output_ground_truth(self):
        self.fixture()
        rows = load_cases(self.raw)
        self.assertEqual([r["behavior_class"] for r in rows], ["harmful", "benign"])
        self.assertEqual([r["ground_truth"] for r in rows], ["AMBIGUOUS", "AMBIGUOUS"])
        self.assertIn("human review", rows[0]["evidence_rule"])
        self.assertIn("unnecessary refusal", rows[1]["expected_behavior"])

    def test_reference_target_is_not_safety_verdict(self):
        self.fixture()
        rows = load_cases(self.raw)
        self.assertEqual(rows[0]["reference_target"], "unsafe completion")
        self.assertNotEqual(rows[0]["expected_behavior"], rows[0]["reference_target"])

    def test_duplicates_within_one_split_are_rejected(self):
        self.fixture()
        self.write_split("harmful", [
            {"Index": "0", "Behavior": "A", "Goal": "foo", "Target": "bar"},
            {"Index": "00", "Behavior": "B", "Goal": "baz", "Target": "qux"},
        ])
        with self.assertRaisesRegex(ValueError, "duplicate case ID"):
            load_cases(self.raw)

    def test_invalid_schema_is_rejected_without_overwriting_output(self):
        self.fixture()
        out = Path(self.tmp.name) / "result.jsonl"
        out.write_text("original-data", encoding="utf-8")
        self.write_split("benign", [{"Index": "X", "Behavior": "B", "Goal": "q", "Target": "t"}])
        with self.assertRaisesRegex(ValueError, "invalid Index"):
            process_dataset(self.raw, out)
        self.assertEqual(out.read_text(encoding="utf-8"), "original-data")

    def test_process_writes_consistent_unique_rows(self):
        self.fixture()
        out = Path(self.tmp.name) / "result.jsonl"
        processed = process_dataset(self.raw, out)
        written = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(processed, written)
        self.assertEqual(len(written), 2)

    def test_committed_dataset_has_two_balanced_splits_and_200_unique_ids(self):
        base = Path(__file__).resolve().parent.parent / "eval" / "dataset"
        raw = base / "raw" / "jailbreakbench"
        output = base / "processed" / "jailbreakbench_processed.jsonl"
        self.assertTrue(output.exists())
        rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(rows), 200)
        self.assertEqual(len(set(row["case_id"] for row in rows)), 200)
        self.assertEqual(Counter(row["behavior_class"] for row in rows), Counter({"harmful": 100, "benign": 100}))
        self.assertTrue(all(row["ground_truth"] == "AMBIGUOUS" for row in rows))
        self.assertEqual(rows, load_cases(raw))


if __name__ == "__main__":
    unittest.main()
