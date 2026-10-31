"""Read-only audit of all 200 JBB prompts and optional local response logs.

From repo root:
py -m security_validation.examples.audit_jbb_dataset
py -m security_validation.examples.audit_jbb_dataset --responses /reports/jbb_live_responses.jsonl
"""
import argparse
import json
from pathlib import Path

from security_validation.src.jbb_batch import audit_jailbreakbench, load_jsonl

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = ROOT / "eval/dataset/processed/jailbreakbench_processed.jsonl"


def main():
    parser = argparse.ArgumentParser(description="Audit JBB response readiness without executing attacks")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--responses", type=Path, default=None)
    parser.add_argument("--reviews", type=Path, default=None)
    parser.add_argument("--include-cases", action="store_true",
                        help="Print case IDs and statuses (never prompts/responses)")
    parser.add_argument("--allow-subset", action="store_true",
                        help="Only for controlled small synthetic fixtures")
    args = parser.parse_args()
    dataset = load_jsonl(args.dataset)
    captured = load_jsonl(args.responses) if args.responses else None
    reviewed = load_jsonl(args.reviews) if args.reviews else None
    report = audit_jailbreakbench(dataset, captured, reviewed,
                                require_full_dataset=not args.allow_subset)
    if not args.include_cases:
        report.pop("cases")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
