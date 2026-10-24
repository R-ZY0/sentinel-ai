# Sentinel AI — Week 01 integration runbook

## Release target

This document describes a **local P0 proof**, not a production-ready security platform.

Expected flow:

1. `POST /targets` creates an authorized local Ollama target.
2. `POST /scans` queues a scan through Redis/Celery.
3. The Backend loads a stable definition from the Cyber #1 attack library (`SPL-001`).
4. The local target is queried using the configured Ollama model.
5. The AI/ML `CanaryRegexJudge` evaluates the response.
6. The Backend stores one `AttackAttempt`, one `Response`, and, if the known canary leaked, a confirmed local-test `Finding` in PostgreSQL.
7. `GET /scans/{id}` reports completed or failed.

The existing `attack_engine` (PyRIT/Garak) runners and the full AI Judge/Presidio/Hybrid suite are staged but are **not yet** part of the backend's Week-01 P0 scan.

## Contract and storage

- `AttackRun.attack_id` / `AttackAttempt.attack_case_id`: stable definition ID, e.g. `SPL-001`.
- `AttackAttempt.id`: unique UUID for a particular execution.
- `Response.attack_attempt_id`: references the execution UUID.
- `Finding.response_id`: references a stored response.
- Heuristic-only detection creates `suspected`; exact planted local canary evidence may be marked `confirmed`.
- Existing rows created before the migration keep a NULL `attack_case_id`.

Schema upgrades run after `create_all` at FastAPI startup. The upgrade is idempotent. Record and inspect migration logs before production deployments.

## Start local demonstration (PowerShell)

From the repository root on `integration/week-01`:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
Invoke-RestMethod http://127.0.0.1:8000/health
```

Register only the configured local target:

```powershell
$target = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/targets -ContentType 'application/json' -Body '{"name":"local-ollama","endpoint":"http://ollama:11434"}'
$scanBody = @{ target_id = $target.id } | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scans -ContentType 'application/json' -Body $scanBody
Invoke-RestMethod "http://127.0.0.1:8000/scans/$($scan.id)"
```

Check again after the Celery task runs, then inspect attempts and findings:

```powershell
docker compose logs --tail 100 celery
docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT id, attack_case_id, status FROM attack_attempts ORDER BY created_at DESC LIMIT 5"'
```

For a controlled disclosure fixture, set `LOCAL_TARGET_MODE=demo_vulnerable` in your local `.env`, restart Celery, and run a new scan. Never use production credentials or third-party targets for this exercise.

## Automated regressions

GitHub Actions:

- `.github/workflows/week1-contracts.yml`: SQLite mapping, migration and Finding tests.
- `.github/workflows/week1-postgres.yml`: real PostgreSQL schema/persistence tests, plus the Backend scan pipeline with a mocked target response.

The workflow tests do not substitute for a real Docker/Ollama smoke test.

## Release acceptance gates

- [ ] Clean Docker Compose startup + healthy API/DB/Redis/Ollama
- [ ] Live local Ollama target scan confirmed in logs and Postgres
- [ ] Protected local response produces no confirmed finding
- [ ] Controlled vulnerable local response produces expected confirmed canary finding
- [ ] Timeout/failure does not produce a false success or confirmed finding
- [ ] All CI jobs green at integration branch head
- [ ] Review and approve the Draft PR before merging into `release/week-01`

## Out of P0 scope

The full 15-probe library, PyRIT/Garak orchestration, RAG target adapter, external API targets, Hybrid/Adaptive Judges, dashboard, CTI enrichment and PDF report are scheduled for later integration milestones. Their files being present does not mean those end-to-end paths are operational.
