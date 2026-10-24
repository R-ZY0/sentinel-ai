# Sentinel AI — Week 1 Integrated Build

**Team setup, local run, testing, evidence review and release handoff**
**Repository:** [`R-ZY0/sentinel-ai`](https://github.com/R-ZY0/sentinel-ai)
**Working branch:** `integration/week-01`
**Review destination:** `release/week-01` through [Pull Request #5](https://github.com/R-ZY0/sentinel-ai/pull/5)
**Baseline documented:** `a63e3d8` (24 October 2026)

> **Scope:** This is a reproducible, local **Week 1 integration / P0 demonstration**, not a production deployment. It explains what is implemented today, not every future feature described in the project roadmap. **Do not push directly to `main` or `release/week-01`.**

## 1. What the team can run today

```text
                       POST /targets, POST /scans
Engineer / Swagger UI  ---------------------------> FastAPI (port 8000)
                                                       |
                                                       v
                                                   Redis queue
                                                       |
                                                       v
                                                  Celery worker
                                                       |
                                         selected Attack Library probes
                                                       |
                                                       v
                                         local Ollama target (protected)
                                                       |
                                         CanaryRegexJudge + BasicJudge
                                                       |
                                                       v
                                     PostgreSQL: Scan -> Attempt -> Response
                                                               -> Finding (if justified)

Optional, explicitly requested review (NOT an automatic Celery stage):
Completed Scan -> read-only PostgreSQL export -> Presidio + LLM Hybrid Judge
              -> per-scan advisory JSONL files in a separate Docker volume
```

### Verified vs. not yet integrated

| Area | Current Week 1 behavior / evidence |
|---|---|
| FastAPI + PostgreSQL + Redis/Celery + local Ollama | Live HTTP→queue→worker→model→DB smoke test **passed (one probe)**. |
| Default scans | **`week1_local`: one `SPL-001` probe**, triggered by `POST /scans`. |
| Complete attack library | **`full_local`: 15 probes**, previously executed live with direct task invocation and persisted in PostgreSQL; not yet demonstrated as a 15-probe scan submitted through the running Celery worker. |
| Findings | Trusted planted synthetic canary can be `confirmed`; heuristic rule matches are `suspected`. The `PWNED` output marker alone is `not_evaluated`, not a vulnerability. |
| Hybrid Judge | **15/15 previously persisted responses reviewed** using a separate, read-only **advisory** workflow; this is not the default scan judging stage. |
| PyRIT / Garak / JailbreakBench | Component/security-validation workflows exist and were exercised separately; the default API scan **does not** orchestrate the full PyRIT/Garak runners. 200 JailbreakBench responses were captured in a separate validation run; this does not establish benchmark Accuracy/F1. |
| CI | At baseline `a63e3d8`, all four GitHub Actions workflows passed on the PR. Recheck checks on your current commit before release. |
| Web UI | **Swagger API docs only:** `http://127.0.0.1:8000/docs`. The `frontend/` directory has no app yet; user dashboard belongs to later Full Stack work. |
| Later-phase features | JWT auth, UI/dashboard, generic external target APIs, automated Adaptive Judge, RAG adapter, CTI/PDF report are **not** validated as working Week 1 end-to-end features. |

## 2. Prerequisites

- Windows 10/11 with **PowerShell 5.1+** or PowerShell 7; instructions below use PowerShell. Other OSes can use equivalent shell commands.
- **Git**, **Docker Desktop** running with its Linux container engine / WSL2 integration, and **Docker Compose v2** (`docker compose`).
- Internet access for first-time container images and the `qwen2.5:0.5b` Ollama model. A larger judge model is only needed for the optional Hybrid review.
- Free RAM/disk for PostgreSQL, Redis, the backend image and Ollama model. Optional Presidio/spaCy and `llama3.2:3b` require substantially more space/RAM.
- Local ports **8000** (API), **5432** (Postgres), **6379** (Redis), **11434** (Ollama) available. Compose binds these to `127.0.0.1` on the host.
- An **authorized local test target** only. No genuine secrets, third-party targets or personal customer data.

Verify prerequisites:

```powershell
git --version
docker --version
docker compose version
docker info
```

If `docker info` fails, start Docker Desktop and wait until its engine is running.

## 3. Get the actual integrated branch

**New teammate / clean checkout:**

```powershell
git clone https://github.com/R-ZY0/sentinel-ai.git
Set-Location .\sentinel-ai
git fetch origin
git switch --track origin/integration/week-01
git status --short --branch
git log -1 --oneline
```

**Existing checkout** (only if your local working tree is clean or you have safely preserved your changes):

```powershell
git switch integration/week-01
git pull --ff-only origin integration/week-01
git status --short --branch
```

Do **not** use `git reset --hard`, `git clean -fd`, or overwrite anyone's uncommitted evidence. The integration branch, **not** the older `main` or `release/week-01`, contains the verified merged Week 1 code pending review.

## 4. Local configuration (.env)

From the repository root:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
```

Set a **unique local-only** `POSTGRES_PASSWORD` before first startup and keep the other Compose values consistent. Relevant settings:

```dotenv
APP_NAME=sentinel-ai
ENVIRONMENT=development
POSTGRES_DB=sentinel
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=REPLACE_WITH_A_UNIQUE_LOCAL_PASSWORD
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
REDIS_HOST=localhost
REDIS_PORT=6379
LOCAL_TARGET_MODE=protected
```

- `.env` is ignored by Git: **never commit it** or print its password into chat/logs.
- Keep `LOCAL_TARGET_MODE=protected` for the normal demo. `demo_vulnerable` is deliberately unsafe and should be used only for an explicitly controlled synthetic-canary fixture.
- Docker Compose supplies internal hostnames (`postgres`, `redis`, `ollama`) to containers; do **not** change the API target to the host's `localhost:11434`. Use `http://ollama:11434` for the target endpoint.
- The running Celery worker does **not** get `SENTINEL_SCAN_PROFILE` from the current Compose definition; its default is `week1_local` even if you add that variable to `.env`. Section 8 provides the supported optional 15-case direct validation.

## 5. Start the integrated stack

```powershell
docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Invalid Compose configuration' }

docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose startup failed' }

docker compose ps -a
```

Services: `postgres`, `redis`, `ollama`, one-off `ollama-init` (pulls `qwen2.5:0.5b`), `api`, and `celery`. **A completed/exited(0) `ollama-init` is expected**, not an app failure. Cold-start image/model downloads can take time; inspect logs if needed:

```powershell
docker compose logs --tail 80 ollama-init
docker compose logs --tail 80 api celery
```

Check health and the installed model:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
docker compose exec -T ollama ollama list
Start-Process 'http://127.0.0.1:8000/docs'
```

Expected `/health`: `{"status":"ok","service":"sentinel-api"}`. The browser opens FastAPI **Swagger UI**, not a React dashboard.

## 6. Run the real API → Redis → Celery → Ollama → PostgreSQL scan

The following PowerShell block creates a new **authorized local-only** Target, submits the default **one-probe** scan and polls its status. **It writes a test Target, Scan, AttackAttempt and Response to your local PostgreSQL**; do not run it against production data.

```powershell
$base = 'http://127.0.0.1:8000'
$targetBody = @{
    name = 'Week1-team-local-test'
    endpoint = 'http://ollama:11434'
} | ConvertTo-Json
$target = Invoke-RestMethod -Method Post -Uri "$base/targets" `
    -ContentType 'application/json' -Body $targetBody

$scanBody = @{ target_id = $target.id } | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post -Uri "$base/scans" `
    -ContentType 'application/json' -Body $scanBody

Write-Host "SCAN_ID: $($scan.id)"
$state = $scan
for ($i = 0; $i -lt 90; $i++) {
    $state = Invoke-RestMethod -Uri "$base/scans/$($scan.id)"
    if ($state.status -in @('completed', 'failed')) { break }
    Start-Sleep -Seconds 2
}
$state | Format-List
if ($state.status -ne 'completed') {
    throw "Scan did not complete; inspect Celery logs. Status=$($state.status)"
}
Write-Host 'API_TO_CELERY_LOCAL_SMOKE: PASS'
```

- `POST /targets` returns a Target ID; `POST /scans` returns `202 Accepted` and a Scan ID. `GET /scans/{id}` returns its state.
- `completed` is the expected execution status. A secure model response usually produces **no confirmed finding**; that is not a test failure.
- `POST /scans` does **not** expose a UI/API switch for the full 15 probes yet.

### Inspect persisted data (read-only)

```powershell
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT id, status, created_at FROM scans ORDER BY created_at DESC LIMIT 5;"'
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT attack_case_id, status, created_at FROM attack_attempts ORDER BY created_at DESC LIMIT 10;"'
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT status, category, severity FROM findings ORDER BY created_at DESC LIMIT 10;"'
```

This interface does not expose HTTP endpoints for finding lists, response details, or scan histories. Those belong to later platform integration.

## 7. Default scan vs. full suite

| Mode | How selected | Expected count | What it proves |
|---|---|---:|---|
| `week1_local` | Default running Celery service in Compose | 1 (`SPL-001`) | Real HTTP enqueue and persistence |
| `full_local` | Explicit environment override on a **separate direct validation** invocation | 15 | The attack library and target calls persist all 15 attempts/responses; **not** proof of 15 jobs through the existing worker queue |

The case library is in `attack_engine/attack_library.py`, the selection is in `backend/app/attack_engine.py`, and persistence/triage is in `backend/app/attack_runner.py`. All direct/live tests remain restricted to the configured local Ollama target.

## 8. Optional: execute all 15 probes on the protected local model

Only for a local team validation run. This block invokes the Celery task function **directly inside a one-off backend image**; it does **not** enqueue through Redis. It creates a new scan and leaves its evidence in PostgreSQL for audit.

```powershell
$fullScript = @'
from uuid import uuid4
from sqlalchemy import select
from app.database import SessionLocal
from app.models import Target, Scan, AttackAttempt, Response
from app.local_target import OLLAMA_BASE_URL, LOCAL_TARGET_MODE
from app.scan_tasks import run_scan
from attack_engine.attack_library import ATTACK_LIBRARY

assert LOCAL_TARGET_MODE == "protected", "Use protected local target only"
target_id, scan_id = uuid4(), uuid4()
with SessionLocal() as db:
    db.add(Target(id=target_id, name="TEAM-WEEK1-FULL15", endpoint=OLLAMA_BASE_URL))
    db.flush()  # Target FK must exist before Scan insert
    db.add(Scan(id=scan_id, target_id=target_id, status="queued"))
    db.commit()
print("FULL_15_SCAN_ID:", scan_id, flush=True)
result = run_scan.run(str(scan_id))  # Direct task call, NOT queue submission
with SessionLocal() as db:
    attempts = list(db.scalars(select(AttackAttempt).where(AttackAttempt.scan_id == scan_id)))
    responses = list(db.scalars(select(Response).join(
        AttackAttempt, Response.attack_attempt_id == AttackAttempt.id
    ).where(AttackAttempt.scan_id == scan_id)))
    assert db.get(Scan, scan_id).status == "completed"
    assert result["mode"] == "full_local" and result["attacks_executed"] == 15
    assert len(attempts) == len(responses) == 15
    assert {a.attack_case_id for a in attempts} == {c.attack_id for c in ATTACK_LIBRARY}
    assert all(a.status == "completed" for a in attempts)
    print("ATTACKS:", len(attempts), "RESPONSES:", len(responses))
print("LOCAL_FULL_15_DIRECT_VALIDATION: PASS")
'@
$fullScript | docker compose run --rm --no-deps -T `
    -e 'SENTINEL_SCAN_PROFILE=full_local' `
    -e 'LOCAL_TARGET_MODE=protected' celery python -
if ($LASTEXITCODE -ne 0) { throw 'Full 15 validation failed' }
```

Keep the emitted `FULL_15_SCAN_ID` for the optional Hybrid Judge review in section 9. Do not treat heuristic acceptance as automatically confirmed compromise. As of the documented validation, the original 15-case run had two *historical* suspected findings (`JB-001`, `PI-001`) and zero trusted exact-canary findings. The `PI-001` marker was later recalibrated; **historical database evidence is not retroactively rewritten**.

## 9. Optional: Hybrid Judge advisory review of a **completed** scan

Read the exact component runbook: [`judge/integration/README.md`](../../judge/integration/README.md). **This is opt-in and read-only with respect to PostgreSQL.** It uses a separate Python 3.11 environment because the default backend image intentionally does not contain the full Presidio/LLM judge dependency stack.

### 9.1 Prepare the separate judge runtime (once per machine)

First pull the judge model into the running Ollama container:

```powershell
docker compose exec -T ollama ollama pull llama3.2:3b
```

Create a **named Python virtual-environment volume**. This downloads Judge Python dependencies and the English spaCy model; it is not needed for the basic API demo:

```powershell
docker run --rm `
    -v sentinel-judge-venv:/opt/venv `
    -v "${PWD}:/work:ro" -w /work `
    python:3.11-slim sh -lc '
        python -m venv /opt/venv &&
        /opt/venv/bin/python -m pip install --upgrade pip &&
        /opt/venv/bin/python -m pip install -r judge/requirements.txt &&
        /opt/venv/bin/python -m spacy download en_core_web_lg
    '
if ($LASTEXITCODE -ne 0) { throw 'Judge environment bootstrap failed' }
```

### 9.2 Export the completed scan from PostgreSQL (read-only)

Replace the placeholder with the **completed** scan UUID printed by section 6 or 8:

```powershell
$scanId = 'REPLACE_WITH_COMPLETED_SCAN_UUID'
$scriptPath = (Resolve-Path .\judge\integration\review_completed_scan.py).Path

docker compose run --rm --no-deps -T --user 0:0 `
    -e 'PYTHONPATH=/app' `
    -e "SENTINEL_EVIDENCE_SCAN_ID=$scanId" `
    -v sentinel-judge-review:/evidence `
    -v "${scriptPath}:/opt/review_completed_scan.py:ro" `
    celery python /opt/review_completed_scan.py export
if ($LASTEXITCODE -ne 0) { throw 'Judge evidence export failed' }
```

### 9.3 Review existing responses with the Hybrid Judge

```powershell
$ollamaContainer = docker compose ps -q ollama
if ([string]::IsNullOrWhiteSpace($ollamaContainer)) {
    throw 'Ollama container is not running'
}

docker run --rm `
    --network "container:$ollamaContainer" `
    -v sentinel-judge-review:/evidence `
    -v sentinel-judge-venv:/opt/venv `
    -v "${PWD}:/work:ro" `
    -v "${scriptPath}:/opt/review_completed_scan.py:ro" `
    -e 'PYTHONPATH=/work/backend:/work' `
    -e "SENTINEL_EVIDENCE_SCAN_ID=$scanId" `
    -e 'SENTINEL_ADVISORY_MODEL=llama3.2:3b' `
    -w /work python:3.11-slim `
    /opt/venv/bin/python /opt/review_completed_scan.py judge
if ($LASTEXITCODE -ne 0) { throw 'Hybrid Judge review failed' }
```

Expected terminal label: `JUDGE_ON_PERSISTED_BACKEND_EVIDENCE: PASS` after every saved response has an advisory decision. The tool validates response SHA-256 hashes, keeps captures **per scan** and supports resume without rejudging completed cases. Results live in the **`sentinel-judge-review` named Docker volume**, under `/evidence/<scan-uuid>/`; they are not new rows in PostgreSQL.

**Interpretation:** `NO_LEAK` = no leak recognized by these detectors, **not** proof the target is safe. The Hybrid Judge does not adjudicate jailbreak compliance or prompt-injection policy override. Advisory `LEAK`/PII signals do **not** automatically create or upgrade `confirmed` findings. This workflow requires the full dependencies and model to be healthy.

## 10. Team regression tests

From a working stack:

```powershell
# Basic API and queue-submit handling
docker compose exec -T api python -m unittest -v app.test_api_errors app.test_scan_submission

# Database pipeline regression suite (mocked model output; currently 6 tests)
# Prefer CI PostgreSQL acceptance for repeatable, isolated DB verification.
# DO NOT run these directly against a shared team PostgreSQL database without
# agreed test isolation, since their setup expects independent fixtures.

# No-dependency integration/judge-bridge contract tests in a disposable image
docker run --rm -e 'PYTHONPATH=/work/backend:/work' `
    -v "${PWD}:/work:ro" -w /work python:3.11-slim `
    python -m unittest -v judge.integration.test_scan_review

# BasicJudge unit regressions without calling Ollama
docker run --rm -e 'PYTHONPATH=/work/backend:/work' `
    -v "${PWD}:/work:ro" -w /work python:3.11-slim `
    python -m unittest -v attack_engine.test_basic_judge
```

GitHub Actions on the latest PR commit are the shared acceptance source of truth:

| CI workflow | Main focus |
|---|---|
| `Week 1 contract regressions` | Shared contracts, cases, canary, Garak, judge-bridge contract tests |
| `Week 1 PostgreSQL acceptance` | Real PostgreSQL + mocked-response backend pipeline tests |
| `Week 1 container build` | Backend/Compose build correctness |
| `Week 1 protected PyRIT regressions` | PyRIT and attack-library regressions |

The full Judge model tests are **not** a dependency-free CI run; they need a separate Ollama model and Presidio/spaCy environment. Existing past local evidence: **16/16** Judge tests passed. Do not relabel those as independently run by a new team member.

## 11. Troubleshooting / FAQ

| Symptom | Likely explanation and action |
|---|---|
| `Cannot connect to Docker daemon` | Start Docker Desktop, then rerun `docker info`. |
| Port 8000/5432/6379/11434 already in use | Stop the conflicting local service; a separately installed Ollama often owns port 11434. Do not expose Compose services on public interfaces to work around this. |
| `api` responds but scan stays `queued` | Run `docker compose ps -a` and `docker compose logs --tail 100 celery`; verify Redis and the one-time Ollama model pull completed. |
| `scan.status=failed` | Inspect `docker compose logs --tail 150 celery`; check the model, target endpoint `http://ollama:11434`, protected mode and DB connectivity. |
| `404 Target not found` | Create a Target first; use the **returned UUID** as `target_id` in `POST /scans`. |
| Scan only runs **one** case | Correct default (`week1_local`). The `full_local` override is deliberately not passed by the running Compose worker. Use section 8 for explicit direct full-suite validation. |
| `ModuleNotFoundError: No module named 'app'` in judge exporter | Its path is `/opt/`; pass `-e PYTHONPATH=/app` when invoking it in the backend container. |
| Judge missing `presidio_analyzer` / `spacy` / Ollama `llama3.2:3b` | Finish optional bootstrap in section 9. Do not install the heavy judge stack into the backend service merely to run the basic demo. |
| Export says scan incomplete/missing or evidence mismatch | Use a **completed** Scan ID; do not edit the immutable capture. Read the error before rerunning. |
| `LF will be replaced by CRLF` | Git's Windows line-ending warning, not test failure. Avoid reformatting unrelated files. |
| Two local canary JSONL files show as modified | These are local evidence artifacts. Do not stage, overwrite, reset, or discard without their owner's instruction. |

**Useful, non-destructive maintenance:**

```powershell
docker compose ps -a
docker compose logs --tail 150 api celery ollama
docker compose stop           # preserves named volumes / existing evidence
docker compose up -d --build # re-create services with current source code
```

**Data safety:** Never suggest `docker compose down -v` for routine troubleshooting. It **deletes** Compose database/model volumes. Do not delete `sentinel-judge-review` or the team's separate JailbreakBench evidence volume. Review logs and Docker volume ownership before cleanup.

## 12. Security, evidence and evaluation rules

1. Test only local/owned targets or targets with explicit authorization. No scraping/probing arbitrary hosts.
2. The only supported backend runner target in this Week 1 build is the configured Ollama endpoint, **not arbitrary URL testing**; accepting a Target registration is not proof the runner supports that endpoint.
3. The canary is synthetic and intentionally planted. Only an **actual trusted canary match** justifies the current narrow `confirmed` leak condition. Heuristic jailbreak indicators remain `suspected`.
4. `PWNED` in a response by itself does not prove a breach of a higher-priority instruction. Historical rows are audit evidence and are not rewritten by current heuristics.
5. Hybrid Judge reports are **advisory disclosure classification**, not true positive/false positive ground truth for all attack families.
6. Collecting 200 JailbreakBench responses with no execution errors does **not** mean 200 successful defenses or validated Accuracy/Precision/Recall/F1. Independent labeling and a frozen evaluation protocol are needed.
7. Store evidence only in controlled local volumes; responses/records can contain synthetic secret-like strings and should not be pushed to Git or shared publicly without review.
8. Docker Compose exposes local development APIs without production authentication or hardening. **Do not make these endpoints internet-accessible.**

## 13. Handoff ownership for the four-person team

| Owner | Week 1 demonstration and handoff |
|---|---|
| **Full Stack** | Starts Compose; validates Swagger/API, Redis/Celery and Postgres; owns next week's actual frontend/dashboard and later API surfaces. |
| **Cyber #1 — Attack Engine** | Maintains 15-case library, protected PyRIT/Garak work, attack selection and repeatability; distinguishes direct full-suite runs from queued API scans. |
| **Cyber #2 — Security Validation** | Reviews `suspected`/`confirmed` evidence, canary trust, safe claims and labeling protocol; audits validation datasets. |
| **AI/ML — Judge** | Maintains Canary/Presidio/LLM/Hybrid judges; runs optional read-only advisory reviews; documents non-calibrated confidence and model requirements. |

Recommended demonstration sequence for a meeting: health → Swagger target creation → one default queued scan → completed status → stored attempt/response → optional 15 direct local run → optional Hybrid advisory review → show CI and PR. Clearly identify separately staged features rather than claiming they're part of the default scan.

## 14. Release Week 1 checklist and safe Git procedure

Before asking for a merge into `release/week-01`:

- [ ] Another teammate can clone **`integration/week-01`** and boot the Compose stack from this README.
- [ ] `/health` returns OK and `POST /targets` → `POST /scans` → completed scan is recorded in PostgreSQL.
- [ ] Real local target runs in **protected** mode; no accidental demo-vulnerable setting.
- [ ] Default one-probe behavior and opt-in 15 direct-probe behavior are labeled accurately.
- [ ] `judge/integration/` advisory-only limitations and model requirements are understood.
- [ ] All four GitHub Actions workflows are **green on the latest commit**.
- [ ] Outstanding limits are documented; no invented Accuracy/F1, production-readiness or queue coverage.
- [ ] PR #5 includes this runbook, a concise test/evidence summary and required reviewers.
- [ ] Changes are reviewed and approved under the repository's branch protection rules.

**Never merge by force or push directly into either protected branch.** When the runbook is added to `integration/week-01`, continue via the **existing PR #5**, whose base is `release/week-01`; do not create a duplicate PR. The code owner/reviewer or permitted maintainer performs the actual merge after checks and approvals. Leave `main` unchanged.

### Safe command to stage the runbook (from repo root)

After placing this file at **`docs/integration/README.md`**:

```powershell
if ((git branch --show-current) -ne 'integration/week-01') {
    throw 'STOP: Wrong branch'
}
git status --short --branch
git add -- docs/integration/README.md
git diff --cached --check
git diff --cached --name-only    # must list ONLY docs/integration/README.md
git commit -m 'docs(week1): add integrated team setup and validation runbook'
git push origin integration/week-01
```

**Do not stage** `eval/dataset/processed/canary_analysis.jsonl` or `eval/dataset/processed/canary_evidence_validation.jsonl` if they appear modified in the local checkout. Do not mark PR #5 ready or merge without team agreement.

## 15. Links and source of truth

- [Active draft PR #5 — integration → release/week-01](https://github.com/R-ZY0/sentinel-ai/pull/5)
- [Existing release-readiness notes](week-01-release-readiness.md) — historical Week 1 baseline; some scope wording predates the 15-case opt-in and newer judge-bridge work.
- [AI/ML Judge details](../../judge/README.md)
- [Read-only Hybrid Judge integration guide](../../judge/integration/README.md)
- [Attack Engine details](../../attack_engine/README.md)
- [Live service definition](../../docker-compose.yml)
- [Local environment example](../../.env.example)
- [Project roadmap and long-term vision](../../README.md)

---

**Final status:** Working and tested local Week 1 integration; **release PR still needs team review and approval**. The frontend/dashboard is **next week's Full Stack work**, not an omitted step in this runbook.
