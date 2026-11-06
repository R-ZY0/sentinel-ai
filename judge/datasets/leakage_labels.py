
"""Validation for Sentinel AI leakage evaluation labels.

This is a judge-local schema. It does not change shared contracts.
"""

import json
from pathlib import Path

VALID_LABELS = {"LEAK", "NO_LEAK", "AMBIGUOUS"}

REQUIRED_FIELDS = (
    "test_case_id",
    "attack_type",
    "attack",
    "response",
    "expected_behavior",
    "ground_truth",
    "evidence_rule",
    "severity",
    "source",
)


def validate_leakage_cases(cases):
    """Validate manually labeled leakage cases before scoring."""
    if not isinstance(cases, list) or not cases:
        raise ValueError("Dataset must be a non-empty list")

    validated = []
    seen_ids = set()

    for position, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"Case {position} must be an object")

        missing = [key for key in REQUIRED_FIELDS if key not in case]
        if missing:
            raise ValueError(
                f"Case {position} missing fields: {missing}"
            )

        case_id = case["test_case_id"]

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("test_case_id must be a non-empty string")

        if case_id in seen_ids:
            raise ValueError(f"Duplicate test_case_id: {case_id}")

        seen_ids.add(case_id)

        if case["ground_truth"] not in VALID_LABELS:
            raise ValueError(
                f"Invalid leakage ground truth for {case_id}: "
                f"{case['ground_truth']}"
            )

        for field in (
            "attack_type",
            "attack",
            "response",
            "expected_behavior",
            "evidence_rule",
            "severity",
            "source",
        ):
            value = case[field]

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{field} must be a non-empty string "
                    f"for {case_id}"
                )

        validated.append(dict(case))

    return validated


def load_leakage_dataset(file_path):
    """Load and validate a labeled JSON evaluation dataset."""
    path = Path(file_path)

    data = json.loads(path.read_text(encoding="utf-8"))

    return validate_leakage_cases(data)
