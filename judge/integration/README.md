# Backend → Hybrid Judge review (advisory only)

This is a **read-only integration path** from persisted Sentinel Backend
`Scan → AttackAttempt → Response` evidence to `judge.hybrid_judge.HybridJudge`.

It uses the existing Backend Docker image to export the raw target responses,
and the separately prepared `sentinel-judge-venv` to evaluate the responses
with the local Ollama judge model. The DB is never updated by this process.
Per-scan evidence is saved under `/evidence/<scan_id>/`; the input JSONL is
immutable and individual advisory decisions are appended for safe restart.

**Never treat `NO_LEAK` as proof of model safety.** This Hybrid Judge detects
potential information disclosures; it does *not* adjudicate jailbreak success,
unsafe compliance, prompt-injection policy override, or over-refusal.
Advisory `LEAK` and Presidio PII detections are **not confirmed findings**.
Independent trusted evidence and review are required to change finding status.
The system's existing Canary + heuristic scan pipeline is unchanged.

From repository root, with Docker Compose running, PowerShell example:

```powershell
$scanId = "<UUID of a completed Backend scan>"
$script = "${PWD}\judge\integration\review_completed_scan.py"

docker compose run --rm --no-deps -T --user 0:0 `
  -e "PYTHONPATH=/app" -e "SENTINEL_EVIDENCE_SCAN_ID=$scanId" `
  -v sentinel-judge-review:/evidence `
  -v "${script}:/opt/review_completed_scan.py:ro" `
  celery python /opt/review_completed_scan.py export

docker run --rm --network container:sentinel-ai-ollama-1 `
  -v sentinel-judge-review:/evidence `
  -v sentinel-judge-venv:/opt/venv `
  -v "${PWD}:/work:ro" `
  -v "${script}:/opt/review_completed_scan.py:ro" `
  -e "PYTHONPATH=/work/backend:/work" `
  -e "SENTINEL_EVIDENCE_SCAN_ID=$scanId" `
  -e "SENTINEL_ADVISORY_MODEL=llama3.2:3b" `
  -w /work python:3.11-slim `
  /opt/venv/bin/python /opt/review_completed_scan.py judge
```

Existing evidence created using the earlier temporary `Downloads` utility
under `/evidence/backend_15_capture.jsonl` is preserved; **this version does
not overwrite or migrate it**. Running this version for the same scan starts
a separate per-scan capture and, if judged, consumes additional judge-model
inference (but never replays attacks against the target).

To run the dependency-free contract tests:

```bash
PYTHONPATH=. python -m unittest judge.integration.test_scan_review -v
```

Limitations: the scan schema currently does not store a calibrated verdict
or immutable evaluation configuration. This review is a manual, explicit
workflow, **not** automatic Celery post-scan execution or a dashboard.
Reviewers should approve the scope before making it automatic.
