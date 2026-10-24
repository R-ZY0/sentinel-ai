import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

OWASP_FILE = BASE_DIR / "security" / "mappings" / "owasp_mapping.json"
CWE_FILE = BASE_DIR / "security" / "mappings" / "cwe_mapping.json"

EXPECTED_TEST_CASES = {
    "TC-001",
    "TC-002",
    "TC-003",
    "TC-004",
    "TC-005",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_mapping(name, data, key):
    mappings = data.get("mappings", [])

    actual_ids = {
        item.get("test_case_id")
        for item in mappings
    }

    missing = EXPECTED_TEST_CASES - actual_ids
    extra = actual_ids - EXPECTED_TEST_CASES

    errors = []

    if missing:
        errors.append(f"{name}: missing test cases: {sorted(missing)}")

    if extra:
        errors.append(f"{name}: unexpected test cases: {sorted(extra)}")

    for item in mappings:
        tc = item.get("test_case_id")
        values = item.get(key)

        if not values:
            errors.append(f"{name}: {tc} has no {key} mapping")

    return errors


def validate_tc005(owasp, cwe):
    errors = []

    owasp_tc005 = next(
        item for item in owasp["mappings"]
        if item["test_case_id"] == "TC-005"
    )

    owasp_ids = {
        item["id"]
        for item in owasp_tc005["owasp"]
    }

    required_owasp = {
        "LLM01:2025",
        "LLM02:2025",
    }

    if owasp_ids != required_owasp:
        errors.append(
            f"TC-005 OWASP mapping mismatch: "
            f"expected {sorted(required_owasp)}, got {sorted(owasp_ids)}"
        )

    cwe_tc005 = next(
        item for item in cwe["mappings"]
        if item["test_case_id"] == "TC-005"
    )

    cwe_ids = {
        item["id"]
        for item in cwe_tc005["cwe"]
    }

    required_cwe = {
        "CWE-1427",
        "CWE-200",
    }

    if cwe_ids != required_cwe:
        errors.append(
            f"TC-005 CWE mapping mismatch: "
            f"expected {sorted(required_cwe)}, got {sorted(cwe_ids)}"
        )

    return errors


def main():
    owasp = load_json(OWASP_FILE)
    cwe = load_json(CWE_FILE)

    errors = []

    errors.extend(
        validate_mapping(
            "OWASP",
            owasp,
            "owasp"
        )
    )

    errors.extend(
        validate_mapping(
            "CWE",
            cwe,
            "cwe"
        )
    )

    errors.extend(validate_tc005(owasp, cwe))

    if errors:
        print("MAPPING VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        raise SystemExit(1)

    print("MAPPING VALIDATION PASSED")
    print("OWASP mappings: TC-001 to TC-005 present")
    print("CWE mappings: TC-001 to TC-005 present")
    print("TC-005 compound mapping: validated")
    print("Day 6 security taxonomy mapping: COMPLETE")


if __name__ == "__main__":
    main()