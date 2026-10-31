# Week 2 Integrated Build

## Included work

- Backend: target CRUD, registration, JWT login, and protected target/scan routes.
- AI: Canary/Regex, Presidio, LLM, and Hybrid baseline judges.
- Attack engine: garak/PyRIT execution, adapters, and normalized AttackRun records.
- Security: TC-001–TC-005 definitions, evidence validation, finding schema, and OWASP/CWE mappings.

## Local startup

Requires Docker Desktop with Linux containers and sufficient disk/RAM for
the backend libraries, spaCy model, and two Ollama models.

Create .env from .env.example only if it does not already exist.
Configure POSTGRES_PASSWORD and generate JWT_SECRET_KEY using auth-api.md.
Keep .env out of Git.

Use these settings:

    LOCAL_TARGET_MODE=protected
    SENTINEL_PIPELINE=week2

From the repository root:

    docker compose config --quiet
    docker compose up -d --build

ollama-init prepares qwen2.5:0.5b and llama3.2:3b, then exits successfully.
API startup creates the additional response_evaluations table.
Existing records are retained.

## Run the integrated API flow

Open http://localhost:8000/docs.

1. Register through POST /auth/register if needed.
2. Use Authorize to log in.
3. Create a target with endpoint http://ollama:11434/.
4. Submit POST /scans with its target_id.
5. Poll GET /scans/{id} using the returned scan ID.

The Week 2 worker executes SPL-001 from the shared attack library.
It places a fresh synthetic canary in the local target's system message.
This particular integration checks TC-002 canary disclosure.

The target reply is saved, then reviewed by B0/B1/B2/B3.
Security validation independently checks the trusted synthetic fixture.
Evaluation documents are stored in response_evaluations.

Only a security-validated LEAK creates a confirmed findings row.
NO_LEAK and AMBIGUOUS outcomes remain in the evaluation record.
The canonical finding document, classification, and pending severity are
preserved in the evaluation's security_result.

The existing findings table receives the same finding ID, response
association, category, confirmed status, unassessed severity, and redacted evidence.
No numeric CVSS score is inferred.

## Tests

Run the backend suite:

    docker compose exec api python -m unittest app.test_week2_pipeline app.test_auth app.test_targets app.test_api_errors app.test_scan_submission app.test_pipeline -v

These tests use controlled target/judge fixtures and PostgreSQL transactions.
Their database changes are rolled back.

Component test instructions are in the attack_engine, judge, and
security_validation handoffs. Use separate garak and PyRIT environments.

For Windows tool tests, set:

    $env:PYTHONPATH = "$PWD;$PWD\backend"

For live Windows scanner checks, also set:

    $env:OLLAMA_BASE_URL = "http://127.0.0.1:11434"
    $env:OLLAMA_MODEL = "qwen2.5:0.5b"
    $env:LOCAL_TARGET_MODE = "protected"

Then run each tool using its own environment:

    .\.venv-pyrit\Scripts\python.exe -m attack_engine.run_pyrit_local
    .\.venv-garak\Scripts\python.exe -m attack_engine.run_garak_local

## Important boundaries

- API scans currently use the shared library probe, not the full garak CLI or PyRIT runner.
- garak/PyRIT live execution and normalization are separate verified component paths.
- Detector hits and PWNED markers are not confirmed leakage findings.
- TC-001–TC-005 have component checks; only TC-002 is wired into this live API flow.
- RAG/PII target execution and automatic full-tool orchestration remain integration gaps.
- Authenticated users currently share targets and scans.
- Raw target replies remain in PostgreSQL; evaluation redaction does not erase them.
- Fresh canaries are synthetic test values, not production credentials.
- A completed scan means execution/evaluation finished, not that the target is universally safe.
- Model judgments may vary, and scans can take minutes on local hardware.

## Controlled vulnerable mode

LOCAL_TARGET_MODE=demo_vulnerable encourages disclosure but does not
guarantee it. Restore protected mode and recreate Celery after a demo.

A positive finding path is verified with controlled integration fixtures.
The live vulnerable-mode run on 2026-10-31 did not disclose the canary.

## Release evidence

See week-02-verification.md for observed results and outstanding gates.
Do not claim CI passed until GitHub Actions has actually completed.