#!/usr/bin/env python3
"""Read-only Backend PostgreSQL -> Hybrid Judge advisory review.

One independent evidence directory per completed scan. Never writes to the
Backend DB or upgrades a finding. The hybrid judge detects disclosure signals,
not successful jailbreak, prompt injection, or policy override.
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from uuid import UUID


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def review_paths(scan_id, evidence_dir=None):
    scan_uuid = UUID(str(scan_id))
    root = Path(evidence_dir or os.environ.get("SENTINEL_JUDGE_EVIDENCE_DIR", "/evidence"))
    directory = root / str(scan_uuid)
    return directory / "backend_capture.jsonl", directory / "hybrid_advisory.jsonl"


def read_jsonl(path):
    if not path.is_file():
        raise FileNotFoundError(f"Evidence is absent: {path}")
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if line.strip():
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError(f"Non-object JSONL record at line {line_no}")
                rows.append(obj)
    return rows


def validate_capture(path, scan_id, required_case_ids=None):
    rows = read_jsonl(path)
    if not rows:
        raise ValueError("The captured scan must contain at least one response")
    expected = str(UUID(str(scan_id)))
    ids = [r.get("case_id") for r in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate attack case IDs in capture")
    if required_case_ids is not None and set(ids) != set(required_case_ids):
        raise ValueError("Unexpected attack case set in capture")
    for row in rows:
        if row.get("scan_id") != expected:
            raise ValueError("Capture belongs to a different scan")
        for field in ("case_id", "prompt", "expected_behavior", "response", "response_sha256"):
            if not isinstance(row.get(field), str) or not row[field]:
                raise ValueError(f"Missing or empty {field}")
        if row["response_sha256"] != digest(row["response"]):
            raise ValueError(f"Response digest mismatch: {row['case_id']}")
    return rows


def validate_advisories(path, captured, scan_id, model=None):
    if not path.exists():
        return []
    rows = read_jsonl(path)
    by_id = {r["case_id"]: r for r in captured}
    seen = set()
    expected = str(UUID(str(scan_id)))
    for row in rows:
        case_id = row.get("case_id")
        if case_id in seen or case_id not in by_id:
            raise ValueError(f"Duplicate or unknown advisory case: {case_id}")
        seen.add(case_id)
        if row.get("scan_id") != expected:
            raise ValueError("Advisory belongs to another scan")
        if row.get("response_sha256") != by_id[case_id]["response_sha256"]:
            raise ValueError(f"Advisory evidence mismatch: {case_id}")
        if model is not None and row.get("judge_model") != model:
            raise ValueError("Cannot resume results from a different judge model")
        if row.get("advisory_only") is not True:
            raise ValueError("Stored verdict lacks advisory-only marker")
        hybrid = row.get("hybrid")
        if not isinstance(hybrid, dict) or hybrid.get("verdict") not in ("LEAK", "NO_LEAK", "AMBIGUOUS"):
            raise ValueError("Invalid hybrid advisory verdict")
    return rows


def export_completed_scan(scan_id, capture_path):
    # Imports intentionally deferred so this script can run in both the Backend
    # Docker image and the separate Judge runtime without mixed dependencies.
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import Scan, AttackAttempt, Response, Finding
    from attack_engine.attack_library import ATTACK_LIBRARY

    index = {case.attack_id: case for case in ATTACK_LIBRARY}
    if len(index) != len(ATTACK_LIBRARY):
        raise ValueError("Duplicate attack case identifiers in library")
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "completed":
            raise ValueError("Requested scan does not exist or has not completed")
        attempts = list(db.scalars(select(AttackAttempt).where(AttackAttempt.scan_id == scan_id)))
        ids = {attempt.attack_case_id for attempt in attempts}
        if not attempts or len(ids) != len(attempts) or not ids.issubset(index):
            raise ValueError("Scan has duplicate or unknown attack IDs")
        result = []
        for attempt in sorted(attempts, key=lambda item: item.attack_case_id):
            case = index[attempt.attack_case_id]
            if attempt.status != "completed" or attempt.payload != case.payload:
                raise ValueError(f"Attempt is incomplete or unexpected: {attempt.attack_case_id}")
            response_rows = list(db.scalars(
                select(Response).where(Response.attack_attempt_id == attempt.id)
            ))
            if len(response_rows) != 1 or not response_rows[0].content.strip():
                raise ValueError(f"Expected one nonempty response: {attempt.attack_case_id}")
            response = response_rows[0]
            finding_rows = list(db.scalars(select(Finding).where(Finding.response_id == response.id)))
            result.append({
                "scan_id": str(scan_id),
                "case_id": attempt.attack_case_id,
                "category": case.category,
                "prompt": case.payload,
                "expected_behavior": case.expected_behavior,
                "response": response.content,
                "response_sha256": digest(response.content),
                "historical_finding_status": [f.status for f in finding_rows],
            })
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in result)
    if capture_path.exists():
        if capture_path.read_text(encoding="utf-8") != content:
            raise ValueError("Existing capture differs: refusing to overwrite preserved evidence")
        print("EXPORTED: existing capture verified (no overwrite)")
    else:
        with capture_path.open("x", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        print("EXPORTED:", len(result), "responses from read-only PostgreSQL session")
    print("SCAN_ID:", scan_id)
    print("CAPTURE:", capture_path)
    print("HISTORICAL_SUSPECTED:", [r["case_id"] for r in result
          if "suspected" in r["historical_finding_status"]])


def summary(scan_id, capture_path, advisory_path):
    captured = validate_capture(capture_path, scan_id)
    decisions = validate_advisories(advisory_path, captured, scan_id)
    counts = Counter(r["hybrid"]["verdict"] for r in decisions)
    print("=== HYBRID JUDGE REVIEW SUMMARY ===")
    print("SCAN_ID:", scan_id)
    print("CAPTURED_BACKEND_RESPONSES:", len(captured))
    print("ADVISORY_DECISIONS:", len(decisions), "/", len(captured))
    for label in ("LEAK", "NO_LEAK", "AMBIGUOUS"):
        print("ADVISORY_" + label + ":", counts[label])
    print("ADVISORY_FLAGS:", [r["case_id"] for r in decisions
          if r["hybrid"]["verdict"] != "NO_LEAK"])
    print("NOT_A_JAILBREAK_OR_PROMPT_INJECTION_VERDICT: True")
    print("HISTORICAL_FINDINGS_UNCHANGED: True")
    print("RESULT_FILE:", advisory_path)
    if len(decisions) != len(captured):
        raise ValueError("Incomplete advisory review; run 'judge' to resume")
    print("JUDGE_ON_PERSISTED_BACKEND_EVIDENCE: PASS")


def evaluate_saved_responses(scan_id, capture_path, advisory_path, model, host):
    captured = validate_capture(capture_path, scan_id)
    previous = validate_advisories(advisory_path, captured, scan_id, model=model)
    done = {r["case_id"] for r in previous}
    if len(done) == len(captured):
        print("All saved responses previously judged; no model calls")
        summary(scan_id, capture_path, advisory_path)
        return

    from judge.hybrid_judge import HybridJudge
    from judge.llm_judge import LLMJudge
    from judge.presidio_judge import PresidioJudge
    from app.local_target import CANARY

    hybrid = HybridJudge(
        llm_judge=LLMJudge(model=model, host=host),
        presidio_judge=PresidioJudge(),
    )
    with advisory_path.open("a", encoding="utf-8") as file:
        for n, item in enumerate(captured, 1):
            case_id = item["case_id"]
            if case_id in done:
                print(f"[{n}/{len(captured)}] {case_id}: RESUMED", flush=True)
                continue
            verdict = hybrid.judge(
                attack=item["prompt"], response=item["response"],
                expected_behavior=item["expected_behavior"],
            )
            record = {
                "scan_id": str(scan_id),
                "case_id": case_id,
                "response_sha256": item["response_sha256"],
                "judge_model": model,
                "advisory_only": True,
                "advisory_category": "disclosure_detection_only",
                "canary_exact_in_response": CANARY in item["response"],
                "canary_in_attack_prompt": CANARY in item["prompt"],
                "hybrid": verdict.to_dict(),
            }
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
            file.flush()
            os.fsync(file.fileno())
            print(f"[{n}/{len(captured)}] {case_id}: {verdict.verdict.value} (ADVISORY ONLY)", flush=True)
    summary(scan_id, capture_path, advisory_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("export", "judge", "summary"))
    parser.add_argument("--scan-id", default=os.environ.get("SENTINEL_EVIDENCE_SCAN_ID"),
                        required=False, help="UUID of existing completed Backend scan")
    parser.add_argument("--model", default=os.environ.get("SENTINEL_ADVISORY_MODEL", "llama3.2:3b"))
    parser.add_argument("--host", default=os.environ.get("SENTINEL_ADVISORY_HOST", "http://127.0.0.1:11434"))
    args = parser.parse_args(argv)
    if not args.scan_id:
        parser.error("--scan-id or SENTINEL_EVIDENCE_SCAN_ID is required")
    scan_id = UUID(args.scan_id)
    capture_path, advisory_path = review_paths(scan_id)
    if args.mode == "export":
        export_completed_scan(scan_id, capture_path)
    elif args.mode == "judge":
        evaluate_saved_responses(scan_id, capture_path, advisory_path, args.model, args.host)
    else:
        summary(scan_id, capture_path, advisory_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"STOP: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
