import json
import tempfile
import unittest
from pathlib import Path

from garak.attempt import ATTEMPT_STARTED, ATTEMPT_COMPLETE
from attack_engine.garak_report_adapter import completed_attempt_runs


def write_report(records):
    directory = tempfile.TemporaryDirectory()
    path = Path(directory.name) / "report.jsonl"
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )
    return directory, path


def record(status, uid="synthetic-uuid"):
    return {
        "entry_type": "attempt",
        "uuid": uid,
        "status": status,
        "prompt": {"text": "Synthetic test prompt"},
        "outputs": [{"text": "Synthetic response"}],
        "detector_results": {},
    }


class TestGarakReportAdapter(unittest.TestCase):

    def test_started_and_completed_are_one_run(self):
        directory, path = write_report([
            record(ATTEMPT_STARTED),
            record(ATTEMPT_COMPLETE),
        ])
        with directory:
            runs = completed_attempt_runs(path)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0].attack_id, "synthetic-uuid")
            self.assertEqual(runs[0].actual_response, "Synthetic response")
            self.assertEqual(runs[0].evaluation_status, "pending")
            self.assertIsNone(runs[0].passed)

    def test_multiple_unique_completed_attempts(self):
        directory, path = write_report([
            record(ATTEMPT_COMPLETE, "a"),
            record(ATTEMPT_COMPLETE, "b"),
        ])
        with directory:
            self.assertEqual(len(completed_attempt_runs(path)), 2)

    def test_duplicate_completed_rejected(self):
        directory, path = write_report([
            record(ATTEMPT_COMPLETE),
            record(ATTEMPT_COMPLETE),
        ])
        with directory:
            with self.assertRaises(ValueError):
                completed_attempt_runs(path)

    def test_missing_output_rejected(self):
        bad = record(ATTEMPT_COMPLETE)
        bad["outputs"] = []
        directory, path = write_report([bad])
        with directory:
            with self.assertRaises(ValueError):
                completed_attempt_runs(path)

    def test_no_completed_attempts(self):
        directory, path = write_report([record(ATTEMPT_STARTED)])
        with directory:
            self.assertEqual(completed_attempt_runs(path), [])


if __name__ == "__main__":
    unittest.main()
