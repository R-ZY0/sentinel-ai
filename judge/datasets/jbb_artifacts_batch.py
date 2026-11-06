
import json
from pathlib import Path

from judge.datasets.jbb_artifacts import load_jbb_artifacts


def load_jbb_artifacts_batch(root_dir):
    root = Path(root_dir)

    if not root.is_dir():
        raise FileNotFoundError(f"Dataset directory not found: {root}")

    cases = []
    seen_ids = set()

    stats = {
        "files": 0,
        "total": 0,
        "usable": 0,
        "skipped": 0,
    }

    for path in sorted(root.rglob("*.json")):
        relative_path = path.relative_to(root)

        # Exclude repository test fixtures from evaluation.
        if "test-artifact" in relative_path.parts:
            continue

        data = json.loads(path.read_text(encoding="utf-8"))

        # Ignore metadata and configuration JSON files.
        if not isinstance(data, dict):
            continue

        if not isinstance(data.get("jailbreaks"), list):
            continue

        file_cases, file_stats = load_jbb_artifacts(path)

        stats["files"] += 1
        stats["total"] += file_stats["total"]
        stats["usable"] += file_stats["usable"]
        stats["skipped"] += file_stats["skipped"]

        for original_case in file_cases:
            case = dict(original_case)

            case["case_id"] = (
                f"jbb:{relative_path.as_posix()}:"
                f"{case['case_id']}"
            )

            if case["case_id"] in seen_ids:
                raise ValueError(
                    f"Duplicate case ID: {case['case_id']}"
                )

            seen_ids.add(case["case_id"])

            case["attack_method"] = relative_path.parts[0]
            case["source_file"] = relative_path.as_posix()

            # Jailbreak success is not leakage ground truth.
            case["leakage_ground_truth"] = None

            cases.append(case)

    return cases, stats
