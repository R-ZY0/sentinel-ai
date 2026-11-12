
import json
import tempfile
import unittest
from pathlib import Path

from judge.datasets.jbb_artifacts import load_jbb_artifacts
from judge.datasets.jbb_artifacts_batch import load_jbb_artifacts_batch


def write_fixture(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"parameters": {}, "jailbreaks": records}),
        encoding="utf-8",
    )


class TestJBBArtifacts(unittest.TestCase):

    def test_single_loader_skips_missing_responses(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"

            write_fixture(path, [
                {
                    "index": 1,
                    "prompt": "Test prompt",
                    "response": "Test response",
                    "jailbroken": False,
                },
                {
                    "index": 2,
                    "prompt": "Another prompt",
                    "response": None,
                },
                {
                    "index": 3,
                    "prompt": None,
                    "response": "Another response",
                },
            ])

            cases, stats = load_jbb_artifacts(path)

            self.assertEqual(stats["total"], 3)
            self.assertEqual(stats["usable"], 1)
            self.assertEqual(stats["skipped"], 2)
            self.assertEqual(len(cases), 1)
            self.assertIsNone(cases[0]["leakage_ground_truth"])

    def test_invalid_jailbreaks_list(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invalid.json"
            path.write_text(
                '{"jailbreaks": "invalid"}',
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_jbb_artifacts(path)

    def test_batch_loader_excludes_test_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)

            write_fixture(
                root / "PAIR" / "black_box" / "model.json",
                [{"index": 1, "prompt": "A", "response": "B"}],
            )
            write_fixture(
                root / "GCG" / "white_box" / "model.json",
                [{"index": 1, "prompt": "C", "response": "D"}],
            )
            write_fixture(
                root / "test-artifact" / "test.json",
                [{"index": 1, "prompt": "E", "response": "F"}],
            )

            cases, stats = load_jbb_artifacts_batch(root)

            self.assertEqual(stats["files"], 2)
            self.assertEqual(stats["total"], 2)
            self.assertEqual(stats["usable"], 2)
            self.assertEqual(len(cases), 2)
            self.assertEqual(
                len({case["case_id"] for case in cases}),
                2,
            )

    def test_missing_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / "does_not_exist"

            with self.assertRaises(FileNotFoundError):
                load_jbb_artifacts_batch(missing)


if __name__ == "__main__":
    unittest.main()
