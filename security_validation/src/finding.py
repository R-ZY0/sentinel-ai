"""Construct and schema-validate a finding without changing shared contracts."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]


def _mapped_items(path: Path, test_case_id: str, field: str) -> list:
    entries = json.loads(path.read_text(encoding="utf-8"))["mappings"]
    matches = [row[field] for row in entries if row["test_case_id"] == test_case_id]
    if len(matches) != 1:
        raise ValueError(f"Missing or duplicate {field} classification")
    raw = matches[0]
    return [raw] if isinstance(raw, dict) else raw


def build_finding(attack_run: dict, validation: dict, *, finding_id: str, root: Path = ROOT) -> dict:
    """Build a finding aligned with security/finding_schema.json.

    Caller owns persistence and approval. Confidence is evidence-check confidence
    for the exact synthetic fixtures; it is not model accuracy or CVSS.
    """
    root = Path(root)
    case_id = attack_run["test_case_id"]
    if validation["test_case_id"] != case_id:
        raise ValueError("Case identifier mismatch")
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("finding_id is required")
    owasp = _mapped_items(root / "security/mappings/owasp_mapping.json", case_id, "owasp")
    cwe = _mapped_items(root / "security/mappings/cwe_mapping.json", case_id, "cwe")
    # Restrict taxonomy entries to the shared schema's allowed fields.
    def normalize(items):
        return [{key: row[key] for key in ("id", "name", "role") if key in row} for row in items]
    finding = {
        "finding_id": finding_id,
        "scan_id": attack_run["scan_id"],
        "test_case_id": case_id,
        "title": f"{case_id} security validation",
        "status": validation["validation_status"],
        "category": validation["category"],
        "confidence": validation["confidence"],
        "evidence": validation["evidence"],
        "classification": {"owasp": normalize(owasp), "cwe": normalize(cwe)},
        "severity": {"cvss_version": "4.0", "score": None, "rating": None,
                     "vector": None, "assessment_status": "pending"},
    }
    schema = json.loads((root / "security/finding_schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(finding)
    if finding["status"] == "confirmed" and not any(
        e["type"] == "leakage" and e["validated"] for e in finding["evidence"]
    ):
        raise ValueError("A confirmed finding requires independently validated leakage evidence")
    return finding
