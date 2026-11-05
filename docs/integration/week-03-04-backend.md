# Week 3–4 backend: targets, scans and database

This delivery covers Member 4's Target APIs and Database + Scan API tasks.
The existing team scanner/judge/validator contracts remain unchanged.

## Backend layout

```text
backend/app/
  main.py              # FastAPI entry point
  database.py          # engine/session configuration
  migrations.py        # additive, versioned schema upgrade
  routers/             # auth, health, targets, scans, attack catalog APIs
  models/              # database entities and relationships
  schemas/             # request/response validation
  services/            # adapters, runner, persistence, judgments, access rules
  tasks/               # Celery scan task
  tools/               # HTTP scanner client/service and subprocess execution
  tests/               # all backend automated tests
```

Stable entry points: `app.main:app`, `app.celery_app:celery_app`,
`app.models` and `app.schemas`. Internal imports and CI test commands now use
the packages above; the Celery task name remains `sentinel.run_scan`.
Teammates' root `attack_engine/`, `judge/`, `security_validation/`, and `tests/`
keep their ownership and purpose.

## Setup and migration

Use the existing `.env` settings from the authentication guide. Additional
`TARGET_ALLOWED_ENDPOINTS` is a comma-separated server-controlled list of exact
approved URLs (including paths); default `http://ollama:11434`.
Client-provided URLs cannot expand that allowlist. Do not place credentials in
target configuration. Generic REST authentication headers are not implemented.

Back up an existing PostgreSQL database before deploying schema changes. Both
API startup and worker startup run the additive `0002_targets_and_scans`
migration. PostgreSQL uses a transaction-scoped advisory lock to serialize
simultaneous startup upgrades. Re-running it preserves data and is safe.
An explicit upgrade is also available:

```powershell
docker compose run --rm --no-deps api python -m app.migrations
```

The migration retains old targets, scans, attempts, responses and findings.
Existing unowned records remain shared among authenticated users; new targets
and scans belong to their creator. Historical authorization defaults to true
for compatibility with the existing local demo. New API registrations default
to `authorized: false` and must explicitly declare authorization for testing.
Existing evidence strings remain untouched; new Week 2 validator-confirmed
findings also create normalized evidence and OWASP/CWE mapping rows.
No destructive downgrade or historical evidence backfill is provided.

## Target API

All routes require the existing Bearer JWT. Another user's private resource
returns 404, including modification, validation, starting and cancellation.

| Route | Result |
| --- | --- |
| `POST /targets` | 201; register a typed target |
| `GET /targets` | list visible targets; `offset`, `limit` (1–500) |
| `GET /targets/{id}` | target configuration and validation status |
| `PUT /targets/{id}` | replace configuration; resets validation status |
| `DELETE /targets/{id}` | 204; rejects targets with scan history (409) |
| `POST /targets/{id}/validate` | 200; `valid`/`invalid` connectivity result |

Example registration:

```json
{
  "name": "Local Ollama",
  "endpoint": "http://ollama:11434/",
  "target_type": "ollama",
  "authorized": true,
  "configuration": {"timeout_seconds": 30, "model": "qwen2.5:0.5b"}
}
```

Types: `local` and `ollama` use Ollama-compatible `/api/chat`; `rest` prepares
generic JSON POST configuration with `prompt_field`, dotted `response_field`,
and optional primitive `static_body`. Validation sends one benign connectivity
prompt and records time/status without saving the model's reply. It does not
prove resistance to attacks. Endpoint credentials/query/fragment, redirects,
environment proxies, missing/non-text replies and replies over 1 MiB are rejected.

Generic REST example configuration:

```json
{
  "name": "Prepared REST target",
  "endpoint": "https://approved-target.example/chat",
  "target_type": "rest",
  "authorized": true,
  "configuration": {"prompt_field": "input", "response_field": "output.text", "static_body": {"model": "demo"}}
}
```

An operator must allowlist that exact REST endpoint before validation can call
it. Scan execution currently supports the canonical configured local Ollama
model only: the existing real PyRIT/garak harness plants privileged canary
fixtures there. REST registration/validation is preparation, not live REST
scanning; incompatible scans return 422 instead of claiming fixture evidence
for an unrelated target. The configuration timeout applies to connectivity
validation; scanners retain their own existing execution timeouts.

## Scan API and state transitions

Wire states remain lowercase for compatibility: `created`, `queued`, `running`,
`completed`, `failed`, `cancelled` (the six Week 4 states).

| Route | Result |
| --- | --- |
| `GET /attacks` | authenticated catalog of selectable attack IDs/engines |
| `POST /scans` | **201 created by default**, stores configuration snapshot |
| `GET /scans` | visible scans; optional status/target_id, offset/limit |
| `GET /scans/{id}` | status, configuration, timestamps, safe error code |
| `POST /scans/{id}/start` | 202 queued; only a created scan can start |
| `POST /scans/{id}/cancel` | 200 cancelled; repeat cancellation is harmless |

Create a scan using the actual ID returned by target registration:

```json
{
  "target_id": "d3b2882b-aabf-4533-ac18-6d82e3b4ac39",
  "configuration": {"engines": ["pyrit", "garak"], "attack_ids": ["PYRIT-PI-001", "GARAK-DAN-001"]},
  "auto_start": false
}
```

The example UUID refers to the existing local demo, not a portable seeded row.
Omitting configuration selects PyRIT and garak defaults. For a smaller library
scan, select `engines: ["library"]`, `attack_ids: ["SPL-001"]`.
All selected engines must have an active compatible catalog attack. Definitions
and target configuration are snapshotted when created; the worker uses those
selected definitions. Changed target configuration requires creating a new scan.
Active queued/running targets cannot be edited. The PyRIT catalog ID
`PYRIT-PI-001` maps to the shared scanner's `PI-001` external case ID.

**Compatibility change:** existing clients expecting POST to queue immediately
must add `"auto_start": true` (returns 202), or call `/start` after creation.

```text
CREATED -> QUEUED -> RUNNING -> COMPLETED / FAILED
   |          |         |
   +----------+---------+----> CANCELLED
```

Duplicate task deliveries cannot claim an already-running/finished job. Queue
submission failures record `queue_submission_failed` and return 503 with a scan
ID. Execution failures record `execution_failed`; detailed tracebacks stay in
server logs. This is at-most-one claim, not a full durable outbox/recovery
system: a hard worker crash after claiming can leave a running scan requiring
operator investigation. Cancellation is cooperative: an in-flight external
call may finish, but cancellation prevents subsequent results/evaluations from
committing and wins over late worker completion. Prior stored history remains.
No force-kill of the shared scanner or Ollama process is attempted.

Core tables: users, targets, scans, scan_configurations, attacks, scan_attacks,
attack_attempts, responses, findings, evidence, vulnerability_mappings,
audit_logs, and existing response_evaluations. Foreign keys link the pipeline;
lookup indexes and unique scan/evaluation/configuration relationships are enforced.
Audit entries record ownership-aware target and scan lifecycle actions without
copying raw prompts, passwords or response text into the audit trail.

## Combined verification

The moved Windows virtual environments still need recreation before use.
Use the containers for the shared verification below instead.

Rebuild once after all edits; requirements are unchanged, so existing dependency
layers can be reused. Rebuild scanner images too because their entry point moved.

```powershell
docker compose config --quiet
docker compose up -d --build api celery pyrit garak
docker compose exec api python -m unittest discover -s app/tests -t . -v
```

Automated tests use controlled replies and database transactions; they do not
replace live scanner acceptance. Check `/health`, log in in Swagger, register an
authorized Ollama target, validate it, create/start a scan, poll its scan ID, and
inspect worker logs and persisted evaluations. Separately create/cancel a scan
before starting it. Confirm it stays cancelled and cannot start.

As of this implementation, **61 backend tests pass locally on an isolated
SQLite database**, including fresh/legacy/repeated migrations, ownership, target
adapter validation, configured selection, start/cancel/failure, existing real-tool
boundaries with controlled outputs, and all-five-scenario evidence/mapping
persistence.
The new CI workflow runs the combined suite against PostgreSQL 16. A broader
local run of **183 tests** also passed, including the security-validation suite
and the existing Week 1 persistence/shared attack-engine boundary regressions.

### Live Docker verification — 2026-11-05

The operator supplied the following terminal and Swagger results from the rebuilt
local stack. This records observed acceptance evidence, not a separate CI run.

- API, Celery, PyRIT and garak images built successfully. PostgreSQL, Redis,
  Ollama and both scanner services were healthy; the model initializer exited.
- The combined backend suite passed against container PostgreSQL:
  `Ran 61 tests in 24.239s — OK`.
- Authorized Ollama target `9e0e4a83-0b00-43f7-88be-2b15c328e5b8` was registered
  with an owner. Target validation returned `valid`, latency 6574 ms.
- Scan `e32e531a-e483-4292-9c26-acc32bf3a68f` preserved the selected
  `PYRIT-PI-001` and `GARAK-DAN-001` configuration, started explicitly, and
  progressed from `created` to `running` to `completed` without an error code.
  Execution ran from 03:55:41.160143Z to 03:57:49.852499Z (about 128.7 seconds).
- Worker logs reported two executed attacks and committed `NO_LEAK` evaluations
  for both engines, with no findings. PyRIT evaluation:
  `8fa3931e-7f31-43e5-88f8-0f5dc5e9e9da`; garak evaluation:
  `a24c5afe-0fb5-44c3-b491-ed7185cc3060`. These are worker-reported persistence
  results; no separate live SQL inspection was supplied.
- A second scan, `27b8d785-3268-48f6-9137-6c89ba46eb4b`, was cancelled before
  execution. Its status became `cancelled`, `started_at` stayed null, and
  `finished_at` was recorded. A subsequent start request was rejected with
  `Only a created scan can be started`.

The live checks establish connectivity, configured two-engine execution and
cancel-before-start behavior. Running cancellation, ownership isolation, and
controlled leak/evidence persistence are covered by automated tests; they were
not separately exercised through Swagger in this session. A `NO_LEAK` result
applies to the tested probes and does not establish general target security.
