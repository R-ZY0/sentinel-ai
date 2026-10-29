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

## Full-repository Windows checkout — developer-reported Week 2 checks

Reported from PowerShell after `git pull --ff-only origin feature/security-validation-week-02` fast-forwarded to `615d982`:

- `py -m unittest discover -s security_validation/tests -p "test_*.py" -v`: **29 tests**, `Ran 29 tests in 0.011s`, `OK` (0 failures).
- `py -m security_validation.examples.run_backend_example`: synthetic TC-002 generated `LEAK / confirmed`, evidence with redacted canary fingerprint, `LLM02:2025`, `CWE-200`, CVSS pending.
- `py -m unittest discover -s tests -p "test_week2_security_cases.py" -v`: **7 tests**, `Ran 7 tests in 0.013s`, `OK` (0 failures).
- `py .\\security\\test_cases\\validate_scenarios.py`: `WEEK 2 SCENARIOS: PASS` (five definitions).
- `py .\\security\\mappings\\validate_mappings.py`: `MAPPING VALIDATION PASSED`, including TC-005 compound mapping.

**At commit `615d982`: 36 test cases across the two test suites passed on the developer's full checkout.** Results are evidence for that checkout, not current GitHub CI or a live target scan.

### Next hardening revision

Subsequent validation hardening adds regression cases for multi-fixture evidence order and weak disclosure claims. The previously observed 29+7 results do **not** certify that new revision; re-run the suites locally before updating the PR test status.

## Full-repository Windows developer run at commit `908e333`

Copied from the user-provided PowerShell log after a successful fast-forward:

- `py -m unittest discover -s security_validation/tests -p "test_*.py" -v`:
  **Ran 36 tests in 0.013s — OK**.
- `py -m unittest discover -s tests -p "test_week2_security_cases.py" -v`:
  **Ran 7 tests in 0.013s — OK**.
- **43 tests total across these two suites, no failures**.
- The regression tests covered multi-fixture precedence, attacker-supplied
  echo, partial-prefix evidence, ambiguous protected-configuration claims,
  and the prior component integration boundary.

These are real developer-reported test results for `908e333`, not CI tests.
The newer HMAC evidence receipt implementation adds further tests; those
remain **unverified on the developer's machine until run and reported**.

## Batch audit revision (post `908e333`)

- 12 HMAC traceability tests and 20 JailbreakBench batch tests added after the last developer-reported 43/43 pass.
- Expected (NOT yet observed) next result: 68 component tests + 7 scenario tests = 75 tests total.
- The default no-response audit must match `security_validation/examples/jbb_expected_summary.json`: 200 source rows, 100 per class, no captured responses, no human adjudication, and all rates uncomputed.
- Run the new commands on the developer checkout before reporting a pass. Do not claim any of the 200 prompts succeeded as attacks or leaked sensitive data.

## Full repository Windows run at commit `9575a606` (developer log, 2026-10-29)

The developer supplied the complete PowerShell log after `git pull --ff-only origin feature/security-validation-week-02`, fast-forward `908e333..9575a60`. This is **user-reported execution**, not an automated CI run.

- `py -m unittest discover -s security_validation/tests -p "test_*.py" -v`: **68 tests, 68 passed, 0 failures**, `Ran 68 tests in 0.032s`, `OK`.
- `py -m security_validation.examples.audit_jbb_dataset`: `200` uniquely indexed dataset prompts, 100 harmful / 100 benign, **200 unadjudicated**, `captured=0`, `pending_capture=200`, `reviewed=0`, `not_reviewable=200`; ASR, accuracy, F1 unset.
- `py -m security_validation.examples.run_jbb_batch_sample`: synthetic 2-case example; 1 captured, 1 reviewed as `safe_refusal`, 1 pending capture, zero live target results.
- `py -m security_validation.examples.run_traceability_example`: synthetic TC-002 receipt generated; `validation_status=confirmed` and `integrity_verified=true`. Random HMAC receipt fingerprints change by execution; they do not assert independent authorization.
- The 7 Week-2 scenario tests **previously passed at commit `908e333`**; this most recent log did not rerun them.
- The 200 source prompts were not executed by `audit_jbb_dataset` and cannot be counted as captured responses or validated vulnerabilities.

**Next evidence gate:** collect actual authorized local target responses using the existing dataset runner, store them outside Git, then use `audit_jbb_dataset --responses <path>`. Do not claim response-level accuracy or attack success until human assessment of the captured text.
