"""Offline example using real Week-1 Backend-shaped record names."""
import json
from pathlib import Path
from security_validation.src import validate_backend_execution

HERE = Path(__file__).resolve().parent

def main():
    request = json.loads((HERE / "backend_input.json").read_text(encoding="utf-8"))
    result = validate_backend_execution(**request)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
