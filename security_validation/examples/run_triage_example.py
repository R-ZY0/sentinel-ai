"""Show triage with genuine checked-in synthetic Finding, no network."""
import json
from pathlib import Path

from security_validation.src import validate_backend_execution
from security_validation.src.triage import triage_finding

HERE = Path(__file__).resolve().parent


def main():
    example = json.loads((HERE / "backend_input.json").read_text(encoding="utf-8"))
    result = validate_backend_execution(**example)
    print(json.dumps(triage_finding(result["finding"]), indent=2))


if __name__ == "__main__":
    main()
