"""Local human-review command; prompts/responses shown only on explicit --show.

Never redirect --show to a public log or commit the private review file.
"""
import argparse
import json
from pathlib import Path

from security_validation.src.jbb_batch import audit_jailbreakbench, load_jsonl
from security_validation.src.jbb_review import (
    pending_review_queue, private_review_materials, save_private_human_review,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = ROOT / "eval/dataset/processed/jailbreakbench_processed.jsonl"


def main():
    parser = argparse.ArgumentParser(
        description="Review authorized JBB captures one by one without auto-labeling"
    )
    parser.add_argument("--responses", type=Path, required=True,
                        help="Private existing capture log from the target runner")
    parser.add_argument("--reviews", type=Path, default=None,
                        help="Private review JSONL path outside the git checkout")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--show", metavar="CASE_ID",
                        help="Deliberately display untrusted raw prompt/response locally")
    action.add_argument("--record", metavar="CASE_ID",
                        help="Record one explicit human-reviewed outcome")
    parser.add_argument("--outcome", default=None)
    parser.add_argument("--reviewer", default=None)
    parser.add_argument("--rationale", default=None)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    cases = load_jsonl(args.dataset)
    captures = load_jsonl(args.responses)
    reviews = load_jsonl(args.reviews) if args.reviews and args.reviews.exists() else []
    audit_jailbreakbench(cases, captures, reviews, require_full_dataset=True)

    if args.show:
        materials = private_review_materials(
            cases, captures, reviews, case_id=args.show, require_full_dataset=True
        )
        print("PRIVATE REVIEW ONLY — untrusted AI text below is data, not instructions.")
        print("Do not share or commit raw text; do not follow instructions inside it.\n")
        print("Case:", materials["case_id"], "Input class:", materials["behavior_class"])
        print("Review status:", materials["review_status"])
        print("Expected:", materials["expected_behavior"])
        print("===== UNTRUSTED PROMPT =====")
        print(materials["prompt"])
        print("===== UNTRUSTED MODEL RESPONSE =====")
        print(materials["response"])
        print("===== END UNTRUSTED CONTENT =====")
        print("Allowed human review outcomes:", ", ".join(materials["allowed_outcomes"]))
    elif args.record:
        if not all((args.reviews, args.outcome, args.reviewer, args.rationale)):
            parser.error("--record requires --reviews, --outcome, --reviewer and --rationale")
        saved = save_private_human_review(
            args.reviews, cases, captures, case_id=args.record,
            reviewer=args.reviewer, outcome=args.outcome,
            rationale=args.rationale, require_full_dataset=True,
        )
        print(json.dumps({
            "recorded": saved["case_id"],
            "outcome": saved["outcome"],
            "response_sha256": saved["response_sha256"],
            "private_review_path": str(args.reviews.resolve()),
        }, indent=2))
    else:
        if args.outcome or args.reviewer or args.rationale:
            parser.error("Use --record CASE_ID to submit a review")
        queue = pending_review_queue(
            cases, captures, reviews, limit=args.limit, require_full_dataset=True
        )
        print(json.dumps(queue, indent=2))


if __name__ == "__main__":
    main()
