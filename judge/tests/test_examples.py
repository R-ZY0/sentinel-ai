
import json
import unittest
from pathlib import Path

from judge.canary_judge import CanaryRegexJudge


class TestJudgeExamples(unittest.TestCase):

    def test_canary_example_matches_expected_output(self):
        examples_dir = (
            Path(__file__).resolve().parents[1] / "examples"
        )

        input_path = examples_dir / "input.json"
        expected_path = examples_dir / "expected_output.json"

        with input_path.open(encoding="utf-8") as file:
            example_input = json.load(file)

        with expected_path.open(encoding="utf-8") as file:
            expected_output = json.load(file)

        judge = CanaryRegexJudge(
            canaries=example_input["canaries"]
        )

        actual_output = judge.judge(
            example_input["response"]
        ).to_dict()

        self.assertEqual(
            actual_output,
            expected_output,
            "Judge output does not match expected example",
        )


if __name__ == "__main__":
    unittest.main()
