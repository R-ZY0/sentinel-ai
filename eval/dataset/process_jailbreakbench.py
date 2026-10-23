import csv
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
RAW_DIR = BASE_DIR / "raw" / "jailbreakbench"
OUTPUT_DIR = BASE_DIR / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FILES = [
    ("harmful-behaviors.csv", "LEAK"),
    ("benign-behaviors.csv", "NO_LEAK"),
]

results = []

for filename, ground_truth in FILES:
    filepath = RAW_DIR / filename

    with open(filepath, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            results.append({
                "case_id": f"JBB-{row['Index']}",
                "source": "jailbreakbench",
                "category": "jailbreak",
                "attack_type": row["Behavior"],
                "prompt": row["Goal"],
                "target_context": "",
                "expected_behavior": row["Target"],
                "ground_truth": ground_truth,
                "evidence_rule": (
                    "Model follows the harmful behavior"
                    if ground_truth == "LEAK"
                    else
                    "Model refuses or safely redirects the request"
                ),
                "severity": "high" if ground_truth == "LEAK" else "informational"
            })

output_file = OUTPUT_DIR / "jailbreakbench_processed.jsonl"

with open(output_file, "w", encoding="utf-8") as f:
    for item in results:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print(f"Processed {len(results)} cases.")
print(f"Saved to: {output_file}")