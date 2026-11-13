# Week 5–6 Attack Engine — Test Evidence & Delivery Checklist

## Verified on developer's Windows machine (2026-11-13)

- Branch: `feature/attack-engine-week5-week6`, initially based on release
  commit `7d62723`.
- Python 3.12.1, pytest 8.3.4, local virtual environment `.venv-week56`.
- 75 selected core, mutation, second-round and regression tests **passed**.
- 23 selected contract and backend integration smoke tests **passed**.
- Final prior acceptance run: **98 passed in 0.87s** with JUnit XML.
- `python -m compileall -q attack_engine` passed.
- Git comparison against `7d62723` confirmed all changes under
  `attack_engine/`; shared `backend/`, `judge/`, `security_validation/`,
  `contracts/` and `docker-compose.yml` unchanged.

Original machine-local QA artifacts:

`C:\Users\pc\AppData\Local\Temp\sentinel-week56-acceptance-20261113-163652\`

Files: `acceptance.xml`, `acceptance.txt`, `changes.txt`, `commits.txt`.
This path is local to the developer and is not automatically available
to reviewers. The final handoff should include a redacted test log copy.

## New example-fixture test

`test_week6_examples.py` verifies that the documented Week 6 Input and Output
match a deterministic synthetic execution. This test was added **after**
the 98-test Windows acceptance run; rerun the full selected suite before
asserting a new Windows acceptance count.

## Reproduce (PowerShell, repository root)

Set `$env:PYTHONPATH` to the repository root and `backend` directory.
Use Python 3.12 with `attack_engine/requirements.txt`,
`backend/requirements.txt` and `pytest==8.3.4` installed.

```powershell
python -m pytest attack_engine/test_week5_mutation.py attack_engine/test_week6_second_round.py attack_engine/test_week6_examples.py -q
```

The selection above does not substitute for optional tool-service tests.

## Not verified by this delivery

- Full PyRIT and Garak suites require their separate pinned tool environments.
- Live authorized-target Docker API/Celery end-to-end adaptive integration.
- Concurrent worker claim/attempt budget serialization (Full Stack ownership).
- Judge and evidence confirmation; `executed` is not a security finding.
- Semantic attack-effectiveness improvements across live models.

## Git/contract safety

- No shared JSON schema changes, no new server API, no database migration.
- All implementation changes are confined to `attack_engine/`.
- `AttackVariant.parent_attack_id` is an attack definition ID, not the DB
  attempt UUID; Full Stack must map and persist attempts explicitly.
- A new feature branch and Pull Request are required; no direct merge or push
  to `main` or the release branch.
