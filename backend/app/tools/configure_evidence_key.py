"""Create the local receipt key once without printing it or changing existing secrets."""
from pathlib import Path
import re
import secrets


def configure(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError("Create .env from .env.example and configure the stack first")
    content = path.read_text(encoding="utf-8-sig")
    expression = re.compile(r"^EVIDENCE_AUDIT_KEY\s*=(.*)$", re.MULTILINE)
    matches = list(expression.finditer(content))
    if len(matches) > 1:
        raise ValueError("Duplicate EVIDENCE_AUDIT_KEY entries need operator review")
    if matches:
        value = matches[0].group(1).strip().strip("\"'")
        if value:
            try:
                valid = len(bytes.fromhex(value)) >= 32
            except ValueError:
                valid = False
            if not valid:
                raise ValueError("Existing evidence key is invalid; it was not replaced")
            return False
        content = expression.sub("EVIDENCE_AUDIT_KEY=" + secrets.token_hex(32), content)
    else:
        content = content.rstrip() + "\n\n# Local evidence receipt signing key; never commit.\nEVIDENCE_AUDIT_KEY=" + secrets.token_hex(32) + "\n"
    if not re.search(r"^WEEK34_TARGET_MODE\s*=", content, re.MULTILINE):
        content += "\nWEEK34_TARGET_MODE=protected\n"
    temporary = path.with_name(".env.week34.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


if __name__ == "__main__":
    changed = configure(Path(__file__).resolve().parents[3] / ".env")
    print("Local evidence signing key configured; value not displayed." if changed else "Existing evidence signing key retained; value not displayed.")
