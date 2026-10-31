# Real scanner connection — verification handoff

The e25abe0 release was a partial integration checkpoint. These changes are on
integration/week-02 and have not been committed or pushed yet. The actual tool
paths were live-verified in scan 964b6108-c0f8-45bf-b0b8-ad5c7ba6e1f8.

## Implemented path

POST /scans -> Redis/Celery -> internal PyRIT/Garak service -> actual protected
Ollama request -> tool AttackRun -> persisted attempt/response -> B0/B1/B2/B3 ->
security validation -> stored evaluation and optional confirmed Finding.

Default WEEK2_ATTACK_ENGINES is pyrit,garak. Each engine is executed sequentially.
library remains an optional engine for the earlier SPL-001 path.

- PyRIT uses the team's PyRITRunner, PromptSendingAttack and protected target.
- Garak uses the official CLI runner, then the team's completed-report adapter.
- Aggregate scanner summaries are never substituted for model responses.
- Garak's stable GARAK-DAN-001 probe ID is distinct from its report attempt UUID.
  The latter is retained in baseline_results.execution.source_attempt_id.
- Each tool request receives a new canary from the backend. The child process
  installs it in the canonical protected target request before execution.
- Shared AttackRun and security schemas are unchanged. The tool envelope is
  backend-owned; completed-response validation rejects mismatched provenance,
  missing replies, duplicate report identifiers and failed executions.
- Tool services have no published host ports or database credentials. They are
  trusted local services, not public APIs or a production isolation boundary.
- Console logs and raw scanner reports are temporary and not returned to callers.
  Actual target replies remain in the existing database response records.
- Tool services always use protected mode, independently of the library demo mode.
- Failures mark the scan failed. Already persisted responses/evaluations remain
  available. Tool failures before a usable response do not create fake findings.

## Automated checks performed by the assistant

2026-10-31: 38 backend and scanner-connection tests passed using isolated temporary
Python 3.12 dependencies and a temporary SQLite database. Existing authentication,
target CRUD, queue submission and Week 1/2 pipeline regressions were included.

New checks cover the tool HTTP/process boundaries, exact fixture installation,
response provenance, PyRIT/Garak results reaching real validation/storage, and a
baseline LEAK indicator not overriding independent security validation.

Scanner and model responses are controlled fixtures in these tests. They are not
proof of actual scanner execution through the new containers.
The user subsequently ran all 38 tests against PostgreSQL successfully and
completed an API scan through BOTH real tool services, baseline judges, security
validation and stored evaluations. See week-02-verification.md for the results.
CI on the updated code remains pending.

## Next local verification

From the repository root, keep SENTINEL_PIPELINE=week2 and LOCAL_TARGET_MODE=protected.
If WEEK2_ATTACK_ENGINES exists in .env, set it to pyrit,garak.

    docker compose config --quiet
    docker compose up -d --build api celery pyrit garak
    docker compose ps

The first tool builds install substantial tool dependencies separately.
Both tool containers must be healthy before the worker starts.

Run the full backend suite against PostgreSQL:

    docker compose exec api python -m unittest app.test_week2_pipeline app.test_tool_client app.test_tool_service app.test_tool_process app.test_auth app.test_targets app.test_api_errors app.test_scan_submission app.test_pipeline -v

Authorize in Swagger and create one new scan for the configured local target.
Do not create multiple scans while waiting: both real tools and their model
judgments now execute in sequence, so a scan can take several minutes.

    docker compose logs --tail=60 celery

Verify logs include execution and evaluation for BOTH pyrit and garak. Then
verify two or more persisted evaluations, their actual payload/response links,
and their execution.engine metadata. Each tool must contribute at least one
usable completed response. Confirm that fixture-based assertions and live
observations are recorded separately.

Re-run the updated CI workflows before advancing release/week-02 or develop.
TC-002 is still the wired evidence scenario; live RAG/PII scenarios and further
tool probes require their own integration and acceptance work.
