# Backend Verification Results

Date: 2026-10-19

## Commands run

```powershell
docker compose exec api python -m unittest app.test_api_errors app.test_scan_submission -v
```

Result:
Ran 4 tests in 0.348s
OK


docker compose exec celery python -m unittest app.test_pipeline -v


Result:
Ran 3 tests in 0.210s
OK


Coverage of these checks
- API database conflicts return a safe 409 response.
- Database failures return a safe 503 response.
- Unexpected API failures return a safe 500 response.
- A Celery queue-submission failure marks the scan as failed.
- A canary leak stores a confirmed finding.
- A safe response produces no finding.
- A target timeout marks the scan and attack attempt as failed.