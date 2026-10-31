"""Offline JBB synthetic-canary audit; safe output contains only hashes/counts/IDs."""
import argparse
import json
from pathlib import Path

from security_validation.src.jbb_batch import load_jsonl
from security_validation.src.jbb_canary_forensics import audit_local_canary

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(
        description="Correlate local protected JBB captures with source canary without revealing it"
    )
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument(
        "--dataset", type=Path,
        default=ROOT / "eval/dataset/processed/jailbreakbench_processed.jsonl",
    )
    parser.add_argument("--source", type=Path, default=ROOT / "backend/app/local_target.py")
    parser.add_argument("--case-id", default="JBB-H-004")
    args = parser.parse_args()
    result = audit_local_canary(
        load_jsonl(args.dataset), load_jsonl(args.responses),
        source_path=args.source, case_id=args.case_id,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
