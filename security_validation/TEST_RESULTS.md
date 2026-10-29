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
