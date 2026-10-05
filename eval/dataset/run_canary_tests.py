import json
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parent.parent

INPUT_FILE = BASE_DIR / "synthetic" / "canary" / "canary_cases.jsonl"
OUTPUT_DIR = BASE_DIR / "processed"
OUTPUT_FILE = OUTPUT_DIR / "canary_results.jsonl"

TARGET_SCRIPT = (
    PROJECT_ROOT
    / "targets"
    / "vulnerable"
    / "vulnerable_target.py"
)


def run_target(prompt):
    result = subprocess.run(
        ["python", str(TARGET_SCRIPT), prompt],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=PROJECT_ROOT,
        timeout=30,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Target failed with exit code {result.returncode}\n"
            f"{result.stderr}"
        )

    return result.stdout


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    cases = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                cases.append(json.loads(line))

    print(f"Loaded {len(cases)} test cases.")
    print()

    results = []

    for index, case in enumerate(cases, start=1):
        print(
            f"[{index}/{len(cases)}] "
            f"{case['case_id']} - {case['attack_type']}"
        )

        try:
            response = run_target(case["prompt"])

            result = {
                "case_id": case["case_id"],
                "category": case["category"],
                "attack_type": case["attack_type"],
                "prompt": case["prompt"],
                "expected_ground_truth": case["ground_truth"],
                "response": response.strip(),
                "target": "vulnerable_local",
            }

            results.append(result)

            print("  ✓ Response captured")

        except Exception as e:
            results.append({
                "case_id": case["case_id"],
                "category": case["category"],
                "attack_type": case["attack_type"],
                "prompt": case["prompt"],
                "expected_ground_truth": case["ground_truth"],
                "response": None,
                "target": "vulnerable_local",
                "error": str(e),
            })

            print(f"  ✗ Error: {e}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for result in results:
            f.write(
                json.dumps(
                    result,
                    ensure_ascii=False
                ) + "\n"
            )

    print()
    print("=" * 50)
    print(f"Completed: {len(results)} cases")
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()