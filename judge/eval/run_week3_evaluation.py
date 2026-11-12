
"""Evaluate the Week 3 Judge on controlled synthetic fixtures.

Run:
    python -m judge.eval.run_week3_evaluation

Results are advisory, not production accuracy or confirmed findings.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from judge.datasets.leakage_labels import load_leakage_dataset
from judge.week3_llm_judge import Week3LLMJudge
from judge.week3_prompt import SYSTEM_PROMPT


ROOT = Path(__file__).resolve().parents[2]

DATASET = ROOT / "judge/datasets/tc_week34_synthetic.json"
SECURITY_TRUTH = ROOT / "security/ground_truth/ground_truth.json"
BASELINE_REPORT = ROOT / "judge/eval/week34_synthetic_results.json"
OUTPUT = ROOT / "judge/eval/week3_synthetic_results.json"


def load_trusted_references():
    """Read security-owned fixtures without changing them."""
    truth = json.loads(
        SECURITY_TRUTH.read_text(encoding="utf-8")
    )

    canary = truth["canary_secrets"][0]["value"]
    document = truth["fake_internal_data"][0]["content"]
    customer = truth["synthetic_pii"][0]

    return {
        "TC-001": {},
        "TC-002": {
            "protected_canary": canary,
        },
        "TC-003": {
            "protected_document": document,
        },
        "TC-004": {
            "protected_email": customer["email"],
            "protected_phone": customer["phone"],
        },
        "TC-005": {
            "protected_canary": canary,
        },
    }


def evaluate():
    cases = load_leakage_dataset(DATASET)
    references = load_trusted_references()

    judge = Week3LLMJudge(
        model="llama3.2:3b",
        seed=42,
    )

    results = []

    for case in cases:
        case_id = case["test_case_id"]
        tc_id = case_id[:6]

        if tc_id not in references:
            raise ValueError(
                f"Unexpected test case: {case_id}"
            )

        print(f"Evaluating {case_id}...", flush=True)

        verdict = judge.judge(
            attack=case["attack"],
            response=case["response"],
            expected_behavior=case["expected_behavior"],
            trusted_references=references[tc_id],
        )

        predicted = verdict.verdict.value

        results.append({
            "test_case_id": case_id,
            "attack_type": case["attack_type"],
            "expected_verdict": case["ground_truth"],
            "predicted_verdict": predicted,
            "match": predicted == case["ground_truth"],
            "confidence": verdict.confidence,
            "evidence_rule": verdict.signals.get(
                "evidence_rule"
            ),
            "matched_reference_names": verdict.signals.get(
                "trusted_reference_matches", []
            ),
            "evaluation_error": verdict.signals.get(
                "evaluation_error"
            ),
            "advisory_only": True,
        })

    matches = sum(row["match"] for row in results)

    previous_baselines = json.loads(
        BASELINE_REPORT.read_text(encoding="utf-8")
    )

    baseline_ids = {
        item["test_case_id"]
        for item in previous_baselines["cases"]
    }
    current_ids = {
        item["test_case_id"]
        for item in results
    }

    if baseline_ids != current_ids:
        raise ValueError(
            "Previous baseline report uses different test cases"
        )

    comparison = {
        baseline: {
            "matches": metrics["matches"],
            "total": metrics["total"],
        }
        for baseline, metrics in previous_baselines[
            "summary"
        ].items()
    }

    comparison["Week3LLMJudge"] = {
        "matches": matches,
        "total": len(results),
    }

    report = {
        "evaluation": "week3_llm_synthetic",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": DATASET.name,
        "dataset_type": "controlled_synthetic",
        "advisory_only": True,
        "security_label_review": "pending",
        "judge_version": "week3-v1",
        "model": {
            "name": judge.model,
            "host": judge.host,
            "temperature": 0,
            "seed": judge.seed,
        },
        "prompt_sha256": hashlib.sha256(
            SYSTEM_PROMPT.encode("utf-8")
        ).hexdigest(),
        "comparison": comparison,
        "cases": results,
        "limitations": [
            "Synthetic match rate is not production accuracy.",
            "Trusted references come from local Security fixtures.",
            "TC-001 has no trusted system-prompt leak fixture.",
            "Exact matching does not detect all partial disclosures.",
            "Ground-truth labels require Security team review.",
            "The evaluator is advisory and is not backend-integrated.",
        ],
    }

    OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    print("\nBaseline comparison:")
    for name, metrics in comparison.items():
        print(
            f"{name}: "
            f"{metrics['matches']}/{metrics['total']}"
        )

    print(f"\nResults saved to: {OUTPUT}")


if __name__ == "__main__":
    evaluate()
