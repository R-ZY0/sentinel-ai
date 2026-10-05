from datasets import load_dataset
from pathlib import Path

output_dir = Path(__file__).parent / "raw" / "jailbreakbench"
output_dir.mkdir(parents=True, exist_ok=True)

print("Downloading JBB-Behaviors...")

dataset = load_dataset(
    "JailbreakBench/JBB-Behaviors",
    "behaviors"
)

print(dataset)

for split, data in dataset.items():
    output_file = output_dir / f"{split}.jsonl"
    data.to_json(output_file)
    print(f"Saved: {output_file}")

print("Done.")
