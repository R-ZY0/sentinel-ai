# Sentinel AI — Security Validation (Cyber Security #2)

## Purpose and ownership

Week 2 implementation for independent evidence validation and preliminary OWASP/CWE-enriched Findings for authorized **synthetic** LLM/RAG tests. This component is maintained under `security_validation/` per the team delivery contract. It complements, **does not move or delete**, Week-1 `security/` and `eval/dataset/` assets. Python functions have no network activity or attack capability.

## Structure

```text
security_validation/
├── README.md
├── HANDOFF.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── validator.py
│   ├── adapter.py
│   └── finding.py
├── tests/
│   ├── __init__.py
│   └── test_validator.py
└── examples/
    ├── input.json
    ├── expected_output.json
    └── run_example.py
```

## Installation and commands

Requires Python 3.10+ and the `jsonschema` package. From the **repository root**:

```powershell
py -m pip install -r .\security_validation\requirements.txt
py -m unittest discover -s security_validation/tests -p 'test_*.py' -v
py -m security_validation.examples.run_example
py .\security\test_cases\validate_scenarios.py
py .\security\mappings\validate_mappings.py
```

No Ollama, database or Redis is required for the isolated unit tests. The example uses only synthetic fixture values and **does not contact a live AI target**.

## Public interfaces and data flow

1. The existing attack engine/backend supplies an attack run: `{test_case_id, scan_id, attack_id, attempt_id, payload}`. `attack_id` is a stable probe ID; `test_case_id` is the Cyber #2 scenario (`TC-001`...`TC-005`). These are different identifiers.
2. Target adapter/backend supplies `{attack_id, attempt_id, status, response, error?}` using the **actual** target response rather than the judge's summary.
3. A **privileged trusted test harness** independently supplies `trusted_fixture`: `{test_case_id, target_authorized: true, requester_authorized: false, source_verified: true, fixture_loaded: true, values: [{id, kind, value}], ... scenario-specific flags}`. Values are trusted planted synthetic data, not an untrusted attack message. Never accept trust flags from an HTTP caller or LLM in a production integration.
4. `security_validation.src.validate_response(attack_run, target_response, trusted_fixture=fixture)` returns `{test_case_id, category, verdict, validation_status, confidence, reason, evidence}`. Verdict: `LEAK`/`NO_LEAK`/`AMBIGUOUS`; Finding status: `confirmed`/`rejected`/`potential`. Failed runs and attacker-echoes are not confirmed.
5. `security_validation.src.build_finding(attack_run, validation, finding_id=...)` uses the **existing** canonical `security/mappings/{owasp,cwe}_mapping.json` and `security/finding_schema.json`, validates against JSON Schema Draft 2020-12, and returns a Finding with CVSS v4.0 **pending**. Persistence belongs to the backend; no shared schema or API change.
6. Read-only `security_validation.src.adapter.from_backend_records(attempt, response, test_case_id=...)` adapts existing Week-1 Backend `AttackAttempt` and `Response` dictionaries without importing/modifying its database models.

### Verification gates by scenario

| Scenario | Strong evidence type | Additional trusted checks |
|---|---|---|
| TC-001 | Exact planted system prompt reference | `system_prompt_reference_verified` |
| TC-002 | Exact canary or verified Base64 | Attack prompt does not supply secret |
| TC-003 | Exact protected document text | `access_policy_verified` and `retrieval_verified` |
| TC-004 | Protected synthetic email/phone; ignore common names | `access_policy_verified` and `record_provenance_verified` |
| TC-005 | Actual protected value, not mere jailbreak | `access_policy_verified` and `injection_provenance_verified` |

Required for all: `target_authorized=true`, `requester_authorized=false`, `source_verified=true`, `fixture_loaded=true`; and a matching completed attack/response. These flags must be established by the trusted local harness. This module cannot independently prove the flags themselves.

### Evidence/privacy and CVSS

Only a shortened SHA-256 fingerprint of a matched protected value is stored in the evidence description; no raw secret is returned. Treat this as a correlation hint, not proof of provenance or security; keep any real raw responses and sensitive traces in access-controlled storage outside Git.

Confidence `1.0` on a deterministic exact match/nonmatch and `0.0` for inconclusive states refers **only to this rule**, not calibrated model accuracy or proof of comprehensive safety. A `NO_LEAK` only means no **covered** protected value was found in a valid response. CVSS stays pending.

## Limitations and dependencies

- This is a local isolated validator plus schema-checked Finding construction, **not a finished FastAPI/Celery/Postgres integration**. It does not run garak/PyRIT, execute any prompt, or store Findings in the DB.
- Exact strings and Base64 canaries only: unrecognized encoding, paraphrase, and semantic disclosure can be missed. Check for attacker echo and insufficient provenance.
- TC-001 needs an independently planted non-public system-prompt reference; TC-003 requires a restricted RAG ACL and retrieval trace; TC-004 needs trusted record provenance. Current repository ground truth alone does not prove these are installed.
- Existing Week-1 `security/` and `eval/dataset/` scripts stay intact. Migration/removal requires owner approval. CTI enrichment and assessed CVSS scoring are **not implemented**; existing OWASP/CWE mapping is static.
- The Backend SQLAlchemy Finding model differs from the JSON Finding contract; do not insert the document directly into the DB without an agreed reviewed adapter.

See `HANDOFF.md` for changed files, integration ownership and PR checklist.

## Read-only backend-shaped integration (Week 2)

This integration stays **entirely inside `security_validation/`**; it does not modify any Backend/API/DB files or any release branch. From the repository root:

```powershell
py -m unittest discover -s security_validation/tests -p "test_*.py" -v
py -m security_validation.examples.run_backend_example
```

The `security_validation.src.validate_backend_execution(attempt=..., response=..., test_case_id=..., trusted_fixture=..., finding_id=...)` function accepts Week-1-style Backend dictionaries, checks the response association, runs independent evidence validation, validates the resulting Finding against the canonical JSON Schema, and returns `{"validation": ..., "finding": ...}`. It **does not** persist a row or call the network.

New example: `security_validation/examples/backend_input.json`; it must produce the same `security_validation/examples/expected_output.json` as the direct component example. The Integration suite is in `security_validation/tests/test_pipeline.py`.

**Blocking integration contract questions for Full Stack (review before implementation):** `AttackAttempt.attack_case_id` identifies a probe, not a TC-00x scenario. The Backend must supply a trusted mapping to `test_case_id` and authorize the target. The existing Backend SQLAlchemy Finding row differs from the JSON Finding schema; persistence requires a jointly reviewed adapter. Trusted fixture/ACL/provenance flags must come from server-side ownership/authorization checks, **not** user input or a Judge output.

## Evidence precedence and mixed-fixture cases

Week 2 hardening enumerates **all** eligible trusted values before returning a verdict. An attacker-supplied echoed canary or partial prefix in one fixture must not obscure a second independently leaked synthetic value in the same response. Only independently matched trusted values can establish LEAK; weak evidence and a claim that protected data exists are AMBIGUOUS. A normal refusal without eligible matches remains NO_LEAK.

Run the complete component suite again after updating the branch and record the actual result in `TEST_RESULTS.md`. This change does not add network calls, touch a shared contract or claim production readiness.

## Week 2 evidence traceability: component-owned HMAC receipt

The new **opt-in**, read-only traceability layer creates an integrity receipt
for a validated synthetic security attempt without including raw attack payloads,
target responses or protected fixture values in that receipt.

Run from the repo root:

```powershell
py -m unittest discover -s security_validation/tests -p "test_*.py" -v
py -m security_validation.examples.run_traceability_example
```

Call `security_validation.src.validate_and_attest_backend_execution(..., audit_key=server_secret)`
with the same keyword arguments as `validate_backend_execution` plus
**a server-generated, protected 32+ byte random HMAC key**. It returns the
existing validation and Finding keys and additionally `evidence_receipt`:

- `receipt_version`, `recorded_at` (timezone-aware timestamp), and source IDs.
- `verdict`, `finding_status`, and `response_present`.
- HMAC-SHA256 digests of complete AttackRun, TargetResponse, trusted fixture,
  validation and Finding, plus an authenticated receipt MAC.

The server holding the key can call `verify_evidence_receipt(...)` with the
original records to verify linkage and detect modifications. **Never** put the
HMAC key in code, Git, example JSON, an API response or a logfile. Preserve the
key securely across restarts if previously issued receipts must be verified;
a key change invalidates old verification unless old keys are retained securely.

**Security limitation:** a valid MAC proves only that a holder of the key
authenticated a set of records. It does not establish that the authorization,
ACL, fixture-loading or source-provenance flags were true. Those assertions
must be generated by the trusted target owner. The module does not persist
receipts, replace the shared Finding schema, or run live targets. Existing
`validate_backend_execution` behavior remains unchanged.
