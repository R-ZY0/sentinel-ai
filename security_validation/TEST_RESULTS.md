# Cyber #2 Week 2 — preliminary test execution record

## Execution environment

- Execution: isolated local Python workspace containing the component source and representative copies of the Week-1 mapping and Finding schema structures.
- Python: 3.13.5
- jsonschema: 4.26.0
- Target: synthetic offline fixtures; **no Ollama/garak/PyRIT or network calls**.

## Commands

```powershell
python -m unittest discover -s security_validation/tests -p 'test_*.py' -v
python -m security_validation.examples.run_example
```

## Observed results

- Unit tests: **17 run, 17 passed**.
- Synthetic example: **LEAK / confirmed**, with evidence fingerprint redacted and CVSS pending.
- Test coverage includes: exact and Base64 canary disclosure, attacker-echo detection, failed/empty responses, refusal, mismatched attempt identifiers, fixture provenance, requester authorization, system-prompt reference, RAG ACL/trace, synthetic PII, prompt-injection provenance, finding case ID enforcement, example snapshot and backend adapter identity.

## Scope and remaining validation

**This is not a GitHub Actions result nor a full-repository test run.** The isolated local workspace used representative mapping/schema copies; the real checked-in taxonomy/schema should also be tested on the user's full repository checkout. No live AttackRun → TargetResponse → Finding persistence was executed.

The team should run the README commands from the repository root and capture exact PowerShell output in the PR. Do not claim a completed Week 2 end-to-end milestone until target/runtime integration and approval gates are complete.

## Full-repository Windows checkout — developer-reported execution

These results were copied from the developer's PowerShell output after a successful `git pull --ff-only origin feature/security-validation-week-02` (24 changed files, fast-forward to `f6e3ff2`). They were **executed on the developer's machine**, not remotely by the connector.

- Repository directory: `C:\Users\moham\sentinel-ai`
- Command: `py -m unittest discover -s security_validation/tests -p "test_*.py" -v`
- Observed: **Ran 17 tests in 0.005s — OK**; no failed tests reported.
- Command: `py -m security_validation.examples.run_example`
- Observed: synthetic TC-002 `LEAK`, `confirmed`, OWASP `LLM02:2025`, CWE `CWE-200`, `cvss_version=4.0`, `score=null`, `assessment_status=pending`; the canary string is redacted from the evidence description.
- The installed Python path in the pip notice contains `pythoncore-3.14-64`; record exact `py --version` and `py -m pip show jsonschema` in the PR when available.
- A pip update notice was printed; it was not a test failure.

### Checks not yet reported from that checkout

- `py .\security\test_cases\validate_scenarios.py`
- `py .\security\mappings\validate_mappings.py`
- Whole-repository and pipeline integration/CI tests
- Live authorized Ollama/RAG smoke tests and persistence into the actual Backend database model

**Interpretation:** isolated component behavior and synthetic example are working on the developer's full checkout. This does **not** certify correctness against arbitrary data or readiness for merge.
