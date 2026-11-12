
"""Week 3/4 synthetic leakage baseline evaluation.

Run: python -m judge.eval.run_week34_synthetic

Advisory evaluation only. Does not create confirmed findings.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from judge.baselines import BaselineConfig, BaselineRunner
from judge.datasets.leakage_labels import load_leakage_dataset


ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = ROOT / "datasets" / "tc_week34_synthetic.json"
OUTPUT_PATH = Path(__file__).with_name(
    "week34_synthetic_results.json"
)

BASELINES = ("B0", "B1", "B2", "B3")


def evaluate():
    cases = load_leakage_dataset(DATASET_PATH)

    config = BaselineConfig(
        canaries=("CANARY_SECRET_12345",),
        regex_patterns=(r"FAKE_CUSTOMER_[A-Z0-9_]+",),
    )

    runner = BaselineRunner(config)
    results = []

    for case in cases:
        case_id = case["test_case_id"]

        print(f"Evaluating {case_id}...", flush=True)

        target_response = {
            "attack_id": case_id,
            "attack": case["attack"],
            "response": case["response"],
            "expected_behavior": case["expected_behavior"],
        }

        comparison = runner.evaluate(target_response)

        if comparison.get("advisory_only") is not True:
            raise ValueError(
                f"Expected advisory result for {case_id}"
            )

        predictions = comparison["baselines"]

        if set(predictions) != set(BASELINES):
            raise ValueError(
                f"Unexpected baseline outputs for {case_id}"
            )

        results.append({
            "test_case_id": case_id,
            "attack_type": case["attack_type"],
            "ground_truth": case["ground_truth"],
            "evidence_rule": case["evidence_rule"],
            "source": case["source"],
            "advisory_only": True,
            "baselines": predictions,
        })

    summary = {}

    for baseline in BASELINES:
        matches = sum(
            row["baselines"][baseline]["verdict"]
            == row["ground_truth"]
            for row in results
        )

        summary[baseline] = {
            "matches": matches,
            "total": len(results),
            "synthetic_match_rate": round(
                matches / len(results), 3
            ),
        }

    report = {
        "evaluation": "week34_synthetic_leakage",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": DATASET_PATH.name,
        "dataset_type": "controlled_synthetic",
        "advisory_only": True,
        "security_label_review": "pending",
        "model": {
            "name": config.llm_model,
            "temperature": 0,
        },
        "summary": summary,
        "cases": results,
        "limitations": [
            "Synthetic fixture results are not production accuracy.",
            "Judge verdicts are not confirmed security findings.",
            "Labels and evidence rules require Security review.",
            "No end-to-end scan is performed.",
        ],
    }

    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\nSynthetic baseline comparison:")
    for name, metrics in summary.items():
        print(
            f"{name}: {metrics['matches']}/{metrics['total']}"
        )

    print(f"\nResults saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    evaluate()
