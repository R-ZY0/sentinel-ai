"""Capture real protected Ollama responses for JailbreakBench input behaviors.

This DOES NOT infer verified safety labels or invent accuracy/F1. Every captured
response requires later human/rubric assessment before scored metrics.
Output is append-only and resumable to a separate report path.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app import local_target

DATASET = Path(__file__).resolve().parent / "processed" / "jailbreakbench_processed.jsonl"


def load_dataset(path):
    cases = [json.loads(s) for s in path.read_text(encoding="utf-8").splitlines() if s.strip()]
    ids = [case["case_id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Dataset has duplicate case IDs; rerun process_jailbreakbench.py")
    if any(c.get("ground_truth") != "AMBIGUOUS" for c in cases):
        raise ValueError("Dataset uses unverified response labels; rerun processor")
    return cases


def balanced_order(cases):
    groups = {name: [c for c in cases if c["behavior_class"] == name] for name in ("harmful", "benign")}
    ordered = []
    for i in range(max(map(len, groups.values()))):
        for name in ("harmful", "benign"):
            if i < len(groups[name]):
                ordered.append(groups[name][i])
    if len(ordered) != len(cases):
        raise ValueError("Unknown behavior_class in dataset")
    return ordered


def load_existing(path, model, mode):
    completed = {}
    if not path.exists():
        return completed
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        case_id = row["case_id"]
        if case_id in completed:
            raise ValueError(f"Duplicate result case ID: {case_id}")
        if row.get("model") != model or row.get("target_mode") != mode:
            raise ValueError("Existing results used another model/target mode; select a new output path")
        completed[case_id] = row
    return completed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DATASET)
    parser.add_argument("--output", type=Path, default=Path("/reports/jbb_live_responses.jsonl"))
    parser.add_argument("--limit", type=int, default=200, help="Balanced harmful/benign cases; 0 = all")
    parser.add_argument("--max-errors", type=int, default=5)
    args = parser.parse_args()
    if local_target.LOCAL_TARGET_MODE != "protected":
        raise SystemExit("STOP: live validation requires LOCAL_TARGET_MODE=protected")
    if args.limit < 0 or args.max_errors < 1:
        parser.error("--limit must be >=0 and --max-errors must be >=1")
    cases = balanced_order(load_dataset(args.input))
    cases = cases if args.limit == 0 else cases[:args.limit]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    completed = load_existing(args.output, local_target.OLLAMA_MODEL, local_target.LOCAL_TARGET_MODE)
    new_errors = 0
    with args.output.open("a", encoding="utf-8") as f:
        for i, case in enumerate(cases, 1):
            cid = case["case_id"]
            digest = hashlib.sha256(case["prompt"].encode("utf-8")).hexdigest()
            if cid in completed:
                if completed[cid].get("prompt_sha256") != digest:
                    raise ValueError(f"Prompt changed for {cid}; select new output path")
                continue
            begun = time.monotonic()
            error = None
            response = None
            try:
                response = local_target.LocalTarget().respond(case["prompt"])
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                new_errors += 1
            result = {
                "case_id": cid,
                "behavior_class": case["behavior_class"],
                "prompt_sha256": digest,
                "model": local_target.OLLAMA_MODEL,
                "target_mode": local_target.LOCAL_TARGET_MODE,
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - begun, 2),
                "response": response,
                "execution_error": error,
                "adjudicated_verdict": None,  # Never call unreviewed response a confirmed fail/pass.
            }
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
            f.flush()
            completed[cid] = result
            print(f"[{i}/{len(cases)}] {cid}: {'ERROR' if error else 'CAPTURED'} ({result['duration_seconds']}s)", flush=True)
            if new_errors >= args.max_errors:
                print(f"STOP: {new_errors} errors reached --max-errors threshold", flush=True)
                break
    selected = {c["case_id"] for c in cases}
    relevant = [row for cid, row in completed.items() if cid in selected]
    successful = sum(bool(row.get("response")) and not row.get("execution_error") for row in relevant)
    failed = sum(bool(row.get("execution_error")) for row in relevant)
    print("=== JBB LIVE CAPTURE SUMMARY ===")
    print("Selected:", len(cases), "Captured:", successful, "Execution errors:", failed)
    print("Behavior classes:", dict(Counter(c["behavior_class"] for c in cases)))
    print("Adjudicated security verdicts: 0 (response labeling still required)")
    print("Report:", args.output)
    if successful != len(cases) or failed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
