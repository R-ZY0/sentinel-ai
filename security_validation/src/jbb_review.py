"""Explicit human-review workflow for protected local JailbreakBench captures.

Never infer safety labels from the input class, reference_target or model output.
All writes are local-only, external to the repository, and bound to the exact
captured response using SHA-256. No network, attack, CTI, or database actions.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile

from .jbb_batch import OUTCOMES, _utc_time, audit_jailbreakbench, load_jsonl

ROOT = Path(__file__).resolve().parents[2]


def pending_review_queue(
    cases: list[dict], captures: list[dict], reviews: list[dict] | None = None,
    *, limit: int = 10, require_full_dataset: bool = False,
) -> dict:
    """Return only case IDs and classes; no prompt, response or rationale."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 200:
        raise ValueError("limit must be an integer between 1 and 200")
    report = audit_jailbreakbench(
        cases, captures, reviews, require_full_dataset=require_full_dataset
    )
    pending = [r for r in report["cases"] if r["review_status"] == "pending_review"]
    pending.sort(key=lambda r: (
        int(r["case_id"].split("-")[2]),
        0 if r["behavior_class"] == "harmful" else 1,
    ))
    return {
        "remaining": len(pending),
        "next_cases": [
            {"case_id": r["case_id"], "behavior_class": r["behavior_class"]}
            for r in pending[:limit]
        ],
        "captured": report["captures"]["captured"],
        "reviewed": report["reviews"]["reviewed"],
    }


def private_review_materials(
    cases: list[dict], captures: list[dict], reviews: list[dict] | None,
    *, case_id: str, require_full_dataset: bool = False,
) -> dict:
    """Return raw content ONLY for an explicitly selected, local private review."""
    report = audit_jailbreakbench(
        cases, captures, reviews, require_full_dataset=require_full_dataset
    )
    row = next((r for r in report["cases"] if r["case_id"] == case_id), None)
    if row is None or row["capture_status"] != "captured":
        raise ValueError("Unknown or noncaptured case")
    dataset_case = next(c for c in cases if c["case_id"] == case_id)
    capture = next(c for c in captures if c["case_id"] == case_id)
    return {
        "case_id": case_id,
        "behavior_class": dataset_case["behavior_class"],
        "expected_behavior": dataset_case["expected_behavior"],
        "prompt": dataset_case["prompt"],
        "response": capture["response"],
        "allowed_outcomes": sorted(OUTCOMES[dataset_case["behavior_class"]]),
        "review_status": row["review_status"],
    }


def make_human_review(
    cases: list[dict], captures: list[dict], existing_reviews: list[dict],
    *, case_id: str, reviewer: str, outcome: str, rationale: str,
    reviewed_at_utc: str | None = None, require_full_dataset: bool = False,
) -> dict:
    """Require explicit human attribution and bind a verdict to captured bytes."""
    report = audit_jailbreakbench(
        cases, captures, existing_reviews, require_full_dataset=require_full_dataset
    )
    row = next((r for r in report["cases"] if r["case_id"] == case_id), None)
    if row is None or row["capture_status"] != "captured":
        raise ValueError("Cannot review unknown, failed or missing response")
    if row["review_status"] == "reviewed":
        raise ValueError("Duplicate review for case ID")
    if outcome not in OUTCOMES[row["behavior_class"]]:
        raise ValueError("Invalid reviewed outcome for behavior class")
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 128:
        raise ValueError("Nonempty reviewer identifier of at most 128 characters required")
    if not isinstance(rationale, str) or len(rationale.strip()) < 10:
        raise ValueError("Human rationale must have at least 10 characters")
    capture = next(c for c in captures if c["case_id"] == case_id)
    response = capture["response"]
    prompt = next(c["prompt"] for c in cases if c["case_id"] == case_id)
    if (len(response) > 16 and response in rationale) or (
        len(prompt) > 16 and prompt in rationale
    ):
        raise ValueError("Rationale must not include raw prompt or response text")
    when = reviewed_at_utc or datetime.now(timezone.utc).isoformat()
    _utc_time(when, "reviewed_at_utc")
    item = {
        "case_id": case_id,
        "reviewer": reviewer.strip(),
        "reviewed_at_utc": when,
        "response_sha256": hashlib.sha256(response.encode("utf-8")).hexdigest(),
        "outcome": outcome,
        "rationale": rationale.strip(),
    }
    # Validate ALL previous reviews and this one before returning to storage.
    audit_jailbreakbench(
        cases, captures, [*existing_reviews, item],
        require_full_dataset=require_full_dataset,
    )
    return item


def save_private_human_review(
    path: str | Path, cases: list[dict], captures: list[dict],
    *, case_id: str, reviewer: str, outcome: str, rationale: str,
    reviewed_at_utc: str | None = None, require_full_dataset: bool = False,
) -> dict:
    """Atomically persist exactly one new human review, outside the repo.

    An O_EXCL lock avoids lost updates from simultaneous reviewers on a shared
    filesystem. A stale .lock must be manually investigated before retry.
    """
    path = Path(path).resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("Private review file must be stored outside the repository")
    if path.suffix.lower() != ".jsonl":
        raise ValueError("Review file must use the .jsonl extension")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        reviews = load_jsonl(path) if path.exists() else []
        item = make_human_review(
            cases, captures, reviews, case_id=case_id, reviewer=reviewer,
            outcome=outcome, rationale=rationale, reviewed_at_utc=reviewed_at_utc,
            require_full_dataset=require_full_dataset,
        )
        temp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n",
                suffix=".tmp", prefix="jbb-review-", dir=path.parent, delete=False,
            ) as handle:
                temp = Path(handle.name)
                for row in [*reviews, item]:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            if temp is not None:
                temp.unlink(missing_ok=True)
        return item
    finally:
        lock.unlink(missing_ok=True)
