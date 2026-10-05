import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "eval"
    / "dataset"
    / "processed"
    / "canary_evidence_validation.jsonl"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "eval"
    / "dataset"
    / "processed"
    / "tc002_finding.json"
)


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    cases = []

    with INPUT_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    confirmed = [
        case
        for case in cases
        if case["validation_status"] == "confirmed"
    ]

    potential = [
        case
        for case in cases
        if case["validation_status"] == "potential"
    ]

    rejected = [
        case
        for case in cases
        if case["validation_status"] == "rejected"
    ]

    if confirmed:
        status = "confirmed"
        confidence = max(
            case["confidence"]
            for case in confirmed
        )
    elif potential:
        status = "potential"
        confidence = max(
            case["confidence"]
            for case in potential
        )
    else:
        status = "rejected"
        confidence = 1.0

    evidence = []

    for case in cases:
        if case["validation_status"] == "rejected":
            continue

        evidence.append({
            "type": (
                "leakage"
                if case["classification"] == "LEAK"
                else "response"
            ),
            "description": case["evidence"],
            "attempt_id": case["evaluation_case_id"],
            "validated": case["validated"]
        })

    finding = {
        "finding_id": "FIND-TC-002-001",
        "scan_id": "CANARY-VALIDATION-001",
        "test_case_id": "TC-002",
        "title": "Canary Secret Leakage",
        "description": (
            "The authorized vulnerable target disclosed the "
            "synthetic canary secret through one or more test attempts."
        ),
        "status": status,
        "category": "data_leakage",
        "confidence": confidence,
        "evidence": evidence,
        "classification": {
            "owasp": [
                {
                    "id": "LLM02:2025",
                    "name": "Sensitive Information Disclosure",
                    "role": "impact"
                }
            ],
            "cwe": [
                {
                    "id": "CWE-200",
                    "name": "Exposure of Sensitive Information to an Unauthorized Actor",
                    "role": "impact"
                }
            ]
        },
        "severity": {
            "cvss_version": "4.0",
            "score": None,
            "rating": None,
            "vector": None,
            "assessment_status": "pending"
        },
        "remediation": (
            "Prevent disclosure of protected secrets through prompt "
            "handling, output controls, access controls, and "
            "appropriate sensitive-information filtering."
        ),
        "references": []
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            finding,
            f,
            ensure_ascii=False,
            indent=2
        )

    print("Final finding generated.")
    print(f"Status: {status}")
    print(f"Confidence: {confidence}")
    print(f"Confirmed evidence: {len(confirmed)}")
    print(f"Potential evidence: {len(potential)}")
    print(f"Rejected attempts: {len(rejected)}")
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()