"""Static Week 2 Cyber #2 scenario/ground-truth/mapping consistency check.

Standard-library only; checks definitions, not live target security.
Run from anywhere: python security/test_cases/validate_scenarios.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IDS = {f"TC-{i:03d}" for i in range(1, 6)}
SECTIONS = (
    "## 1. Objective and category", "## 2. Trusted fixture and preconditions",
    "## 3. Attack input", "## 4. Expected safe behavior",
    "## 5. Expected vulnerable behavior", "## 6. Response-level ground truth",
    "## 7. OWASP / CWE", "## 8. Severity and finding policy",
    "## 9. Execution and acceptance", "## 10. Integration-specific notes",
)

def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def mapping_ids(item, field):
    value = item[field]
    if isinstance(value, dict):
        value = [value]
    return {entry["id"] for entry in value}

def audit(root=ROOT, manifest_override=None):
    root = Path(root)
    errors = []
    manifest = manifest_override or read_json(root / "security/test_cases/week2_scenarios.json")
    entries = manifest.get("test_cases", [])
    observed_ids = [item.get("test_case_id") for item in entries]
    if len(observed_ids) != len(set(observed_ids)):
        errors.append("Duplicate test_case_id")
    if set(observed_ids) != IDS:
        errors.append(f"Expected {sorted(IDS)}, got {sorted(set(observed_ids))}")
    gt = read_json(root / "security/ground_truth/ground_truth.json")
    owasp = {m["test_case_id"]: m for m in read_json(root / "security/mappings/owasp_mapping.json")["mappings"]}
    cwe = {m["test_case_id"]: m for m in read_json(root / "security/mappings/cwe_mapping.json")["mappings"]}
    finding = read_json(root / "security/finding_schema.json")
    categories = set(finding["properties"]["category"]["enum"])
    for entry in entries:
        case_id = entry.get("test_case_id", "<unknown>")
        doc_path = root / entry.get("document", "missing.md")
        if not doc_path.is_file():
            errors.append(f"{case_id}: missing documentation")
        else:
            doc = doc_path.read_text(encoding="utf-8")
            for section in SECTIONS:
                if section not in doc:
                    errors.append(f"{case_id}: missing section {section}")
            if doc.count("```") % 2:
                errors.append(f"{case_id}: unclosed fenced code block")
        if entry.get("category") not in categories:
            errors.append(f"{case_id}: unknown finding category")
        if entry.get("cvss_assessment_status") != "pending":
            errors.append(f"{case_id}: CVSS cannot be pre-assessed")
        if not entry.get("requires_independent_evidence"):
            errors.append(f"{case_id}: missing independent evidence requirement")
        for taxonomy, mappings, key in (("OWASP", owasp, "owasp"), ("CWE", cwe, "cwe")):
            configured = mappings.get(case_id)
            if not configured or mapping_ids(configured, key) != set(entry.get(taxonomy.lower() + "_ids", [])):
                errors.append(f"{case_id}: {taxonomy} mapping mismatch")
        prompt = entry.get("attack_prompt", "")
        if not prompt.strip():
            errors.append(f"{case_id}: empty attack prompt")
        for ref in entry.get("ground_truth_references", []):
            collection, id_ = ref.get("collection"), ref.get("id")
            if collection == "trusted_target_configuration":
                if ref.get("state") != "fixture_required":
                    errors.append(f"{case_id}: system prompt fixture must be marked as required")
                continue
            matches = [x for x in gt.get(collection, []) if x.get("id") == id_]
            if len(matches) != 1:
                errors.append(f"{case_id}: missing or ambiguous trusted fixture {collection}/{id_}")
                continue
            item = matches[0]
            protected_values = [item.get(k) for k in ("value", "email", "phone", "content")]
            if any(isinstance(v, str) and len(v) > 3 and v in prompt for v in protected_values):
                errors.append(f"{case_id}: attacker prompt contains a protected fixture value")
    return errors

def main():
    errors = audit()
    if errors:
        print("WEEK 2 SCENARIOS: FAILED")
        for error in errors:
            print(" -", error)
        raise SystemExit(1)
    print("WEEK 2 SCENARIOS: PASS (5 definitions, trusted references, OWASP/CWE, documentation)")
    print("NOTE: Static check only; does not prove target execution or detect data leakage.")

if __name__ == "__main__":
    main()
