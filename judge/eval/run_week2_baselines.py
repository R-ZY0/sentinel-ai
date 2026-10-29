"""Week 2 synthetic comparison using the judge-owned BaselineRunner.

Run from repository root: python -m judge.eval.run_week2_baselines
This creates an advisory report; it never produces confirmed Findings.
"""
import json
from pathlib import Path

from judge.baselines import BaselineConfig, BaselineRunner

CASES_PATH = Path(__file__).with_name("evaluation_cases.json")
RESULTS_PATH = Path(__file__).with_name("week2_baseline_results.json")
BASELINE_NAMES = ("B0", "B1", "B2", "B3")
VALID_VERDICTS = {"LEAK", "NO_LEAK", "AMBIGUOUS"}


def evaluate_cases(cases, runner):
    """Evaluate synthetic examples with an injected runner (testable offline)."""
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a non-empty list")
    seen_ids = set()
    results = []
    for case in cases:
        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id.strip() or case_id in seen_ids:
            raise ValueError("case ids must be unique non-empty strings")
        seen_ids.add(case_id)
        expected = case["expected_verdict"]
        if expected not in VALID_VERDICTS:
            raise ValueError(f"invalid expected verdict for {case_id}")
        target_response = {
            "attack_id": case_id,
            "attack": case["attack"],
            "response": case["response"],
            "expected_behavior": case["expected_behavior"],
        }
        comparison = runner.evaluate(target_response)
        if comparison.get("advisory_only") is not True:
            raise ValueError("baseline evaluation must remain advisory")
        baselines = comparison["baselines"]
        if set(baselines) != set(BASELINE_NAMES):
            raise ValueError("expected B0/B1/B2/B3 in result")
        results.append({
            "id": case_id,
            "case_type": case.get("case_type", "synthetic"),
            "expected_verdict": expected,
            "advisory_only": True,
            "baselines": baselines,
        })
    summary = {}
    for baseline in BASELINE_NAMES:
        matches = sum(row["baselines"][baseline]["verdict"] == row["expected_verdict"] for row in results)
        summary[baseline] = {
            "matches": matches,
            "total": len(results),
            "sample_match_rate": round(matches / len(results), 3),
        }
    return {
        "advisory_only": True,
        "dataset": "synthetic Week 1 evaluation fixtures; not production accuracy",
        "baselines": {"B0": "Canary/Regex", "B1": "Presidio", "B2": "LLM", "B3": "Hybrid"},
        "cases": results,
        "summary": summary,
    }


def main():
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    runner = BaselineRunner(BaselineConfig(
        canaries=("CANARY_SECRET_12345",),
        regex_patterns=(r"FAKE_CUSTOMER_[A-Z0-9_]+",),
    ))
    report = evaluate_cases(cases, runner)
    RESULTS_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{'CASE':<11}{'EXPECTED':<13}{'B0':<12}{'B1':<12}{'B2':<12}{'B3':<12}")
    print("-" * 72)
    for row in report["cases"]:
        verdicts = [row["baselines"][name]["verdict"] for name in BASELINE_NAMES]
        print(f"{row['id']:<11}{row['expected_verdict']:<13}" + "".join(f"{v:<12}" for v in verdicts))
    print("\nSynthetic fixture match rates (not production accuracy):")
    for name, metrics in report["summary"].items():
        print(f"{name}: {metrics['matches']}/{metrics['total']} ({metrics['sample_match_rate']:.0%})")
    print(f"\nAdvisory results: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
