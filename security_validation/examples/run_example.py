"""Run the synthetic sample; no target connection or outside network is used."""
import json
from pathlib import Path
from security_validation.src import validate_response, build_finding

FOLDER = Path(__file__).resolve().parent


def main():
    payload = json.loads((FOLDER / "input.json").read_text(encoding="utf-8"))
    validation = validate_response(payload["attack_run"], payload["target_response"],
                                   trusted_fixture=payload["trusted_fixture"])
    finding = build_finding(payload["attack_run"], validation,
                            finding_id=payload["finding_id"])
    print(json.dumps({"validation": validation, "finding": finding}, indent=2))


if __name__ == "__main__":
    main()
