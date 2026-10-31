"""Read-only JailbreakBench batch audit and optional human-adjudication join.

Data classes (harmful/benign) are prompts, NOT response-level security
verdicts. This module never executes an attack or auto-assigns LEAK/NO_LEAK.
No prompt, raw response, reference_target or review rationale is emitted.
"""
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

CASE_PATTERN = re.compile(r"^JBB-([HB])-([0-9]{3})$")
HEX_SHA256 = re.compile(r"^[a-f0-9]{64}$")
OUTCOMES = {
    "harmful": {"harmful_compliance", "safe_refusal", "inconclusive"},
    "benign": {"appropriate_help", "over_refusal", "inconclusive"},
}


def load_jsonl(path: str | Path) -> list[dict]:
    """Read a UTF-8 JSONL source; fail on malformed data, don't skip records."""
    path = Path(path)
    rows = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at line {line_number}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"JSONL line {line_number} must be an object")
            rows.append(row)
    return rows


def _unique(rows: list[dict], source: str) -> dict[str, dict]:
    result = {}
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"{source}: non-object at row {index}")
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not CASE_PATTERN.fullmatch(case_id):
            raise ValueError(f"{source}: invalid case ID at row {index}")
        if case_id in result:
            raise ValueError(f"{source}: duplicate case ID {case_id}")
        result[case_id] = row
    return result


def _utc_time(value: object, field: str):
    if not isinstance(value, str):
        raise ValueError(f"{field}: timezone-aware ISO 8601 timestamp required")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field}: malformed timestamp") from None
    if date.tzinfo is None or date.utcoffset() is None:
        raise ValueError(f"{field}: timestamp must include timezone")


def _safe_text(value, field: str):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: required nonempty string")
    return value


def audit_jailbreakbench(
    cases: list[dict],
    captures: list[dict] | None = None,
    reviews: list[dict] | None = None,
    *,
    require_full_dataset: bool = False,
) -> dict:
    """Audit JBB input coverage, captured output and independently reviewed outcomes.

    Captures use eval/dataset/run_jailbreakbench_local.py JSONL rows.
    Reviews are a separate, explicitly human-verified file, each containing
    case_id, reviewer, reviewed_at_utc, response_sha256, outcome, rationale.
    Only output metadata and counts; never output harmful prompts or replies.
    """
    if not isinstance(cases, list) or captures is not None and not isinstance(captures, list):
        raise TypeError("cases and captures must be lists")
    if reviews is not None and not isinstance(reviews, list):
        raise TypeError("reviews must be a list")
    dataset = _unique(cases, "dataset")
    classes = Counter()
    for case_id, case in dataset.items():
        prefix, index = CASE_PATTERN.fullmatch(case_id).groups()
        behavior = case.get("behavior_class")
        if behavior != {"H": "harmful", "B": "benign"}[prefix]:
            raise ValueError(f"{case_id}: incompatible behavior_class")
        if (case.get("source") != "jailbreakbench"
                or case.get("category") != "jailbreak"):
            raise ValueError(f"{case_id}: wrong source/category")
        _safe_text(case.get("prompt"), f"{case_id} prompt")
        _safe_text(case.get("expected_behavior"), f"{case_id} expected_behavior")
        if case.get("ground_truth") != "AMBIGUOUS":
            raise ValueError(f"{case_id}: unverified response ground truth")
        if str(int(index)) != str(int(case.get("source_index", "-1"))):
            raise ValueError(f"{case_id}: source_index does not match ID")
        classes[behavior] += 1
    if require_full_dataset:
        expected_ids = {
            f"JBB-{code}-{i:03d}" for code in ("H", "B") for i in range(100)
        }
        if set(dataset) != expected_ids:
            raise ValueError("Full JailbreakBench audit requires exactly 200 H/B indexed cases")

    captured = _unique(captures or [], "captures")
    reviewed = _unique(reviews or [], "reviews")
    unknown_captures = captured.keys() - dataset.keys()
    unknown_reviews = reviewed.keys() - dataset.keys()
    if unknown_captures or unknown_reviews:
        raise ValueError("Captured/reviewed IDs not present in the dataset")

    # All captures in one report must belong to one model run.
    models = set()
    status_counts = Counter()
    review_counts = Counter()
    rows = []
    for case_id in sorted(dataset):
        case = dataset[case_id]
        capture = captured.get(case_id)
        state = "pending_capture"
        response = None
        if capture is not None:
            if capture.get("behavior_class") != case["behavior_class"]:
                raise ValueError(f"{case_id}: capture behavior class mismatch")
            expected_sha = hashlib.sha256(case["prompt"].encode("utf-8")).hexdigest()
            if capture.get("prompt_sha256") != expected_sha:
                raise ValueError(f"{case_id}: capture prompt fingerprint mismatch")
            model = _safe_text(capture.get("model"), f"{case_id} model")
            models.add(model)
            if capture.get("target_mode") != "protected":
                raise ValueError(f"{case_id}: expected protected authorized target")
            _utc_time(capture.get("captured_at_utc"), f"{case_id} captured_at_utc")
            error = capture.get("execution_error")
            response = capture.get("response")
            if error is not None and (not isinstance(error, str) or not error.strip()):
                raise ValueError(f"{case_id}: malformed execution_error")
            if response is not None and not isinstance(response, str):
                raise ValueError(f"{case_id}: response must be text or null")
            if error is not None:
                state = "execution_error"
            elif not response or not response.strip():
                state = "empty_response"
            else:
                state = "captured"
        status_counts[state] += 1
        review_status = "not_reviewable" if state != "captured" else "pending_review"
        outcome = None
        review = reviewed.get(case_id)
        if review is not None:
            if state != "captured":
                raise ValueError(f"{case_id}: cannot review missing/failed response")
            outcome = review.get("outcome")
            if outcome not in OUTCOMES[case["behavior_class"]]:
                raise ValueError(f"{case_id}: invalid outcome for behavior class")
            _safe_text(review.get("reviewer"), f"{case_id} reviewer")
            _safe_text(review.get("rationale"), f"{case_id} rationale")
            _utc_time(review.get("reviewed_at_utc"), f"{case_id} reviewed_at_utc")
            digest = hashlib.sha256(response.encode("utf-8")).hexdigest()
            if review.get("response_sha256") != digest:
                raise ValueError(f"{case_id}: stale adjudication fingerprint")
            review_status = "reviewed"
            review_counts[outcome] += 1
        review_counts[review_status] += 1
        rows.append({
            "case_id": case_id,
            "behavior_class": case["behavior_class"],
            "capture_status": state,
            "review_status": review_status,
            "reviewed_outcome": outcome,
        })
    if len(models) > 1:
        raise ValueError("Captures from multiple models need separate reports")

    # Never turn an input class, reference_target, automatic classifier, or
    # a missing response into an observed successful jailbreak.
    return {
        "report_version": "1.0",
        "dataset": {
            "cases": len(dataset),
            "unique_ids": len(dataset),
            "behavior_classes": dict(sorted(classes.items())),
            "unadjudicated_ground_truth": len(dataset),
        },
        "captures": {
            "model": next(iter(models)) if models else None,
            "captured": status_counts["captured"],
            "execution_errors": status_counts["execution_error"],
            "empty_responses": status_counts["empty_response"],
            "pending_capture": status_counts["pending_capture"],
        },
        "reviews": {
            "reviewed": review_counts["reviewed"],
            "pending_review": review_counts["pending_review"],
            "not_reviewable": review_counts["not_reviewable"],
            "reviewed_outcomes": {
                kind: review_counts[kind] for kind in sorted(
                    OUTCOMES["harmful"] | OUTCOMES["benign"]
                )
            },
        },
        "metrics": {
            "response_level_attack_success_rate": None,
            "accuracy": None,
            "f1": None,
            "status": "requires_confirmed_human_response_review_and_metric_definition",
        },
        "cases": rows,
    }
