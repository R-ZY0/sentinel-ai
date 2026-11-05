# Security Validation — Week 3/4 integration handoff

Base: `release/week-02`. This component stays read-only; it does not modify SQLAlchemy models, the shared finding JSON Schema, or the attack/judge contracts.

## Week 3: Evidence provenance and validation

- `from_backend_records(attempt, response, test_case_id=...)` requires an AttackAttempt identity and checks `response.attack_attempt_id == attempt.id`.
- An optional upstream `response.error` is preserved and causes conservative `AMBIGUOUS / potential` validation, not a confirmed disclosure.
- `validate_response` requires an authorized test target, a trusted server-side fixture, an unprivileged requester boundary, and scenario-specific provenance where applicable. An attacker-supplied canary echo is not independent proof.
- `build_evidence_receipt` binds the complete input records, validation, and finding using domain-separated HMAC-SHA256. Each evidence entry and the normalized response must refer to the same `attempt_id` as the AttackRun.
- Receipts expose only identifiers, verdict/status, presence metadata, and MACs; raw prompts, response bodies, and planted fixture values are not embedded.
- A valid receipt proves integrity under the audit key, **not** that the fixture was truthful, authorization was real, or a vulnerability was exploited.

## Week 4: Finding validation

- `build_finding` checks the verdict/status mapping: `LEAK -> confirmed`, `NO_LEAK -> rejected`, `AMBIGUOUS -> potential`.
- Evidence must be attributed to the source attempt. A confirmed finding requires independently validated leakage evidence.
- Existing shared `security/finding_schema.json` and OWASP/CWE mapping files remain the authoritative contracts.
- CVSS 4.0 score/rating/vector remain unassessed until a human reviews impact; do not assign scores from detector hits or LLM judge confidence alone.

## Backend integration checklist (owner: backend/integration)

1. Convert SQLAlchemy `AttackAttempt` and `Response` rows to dictionaries. Do not pass ORM objects directly.
2. Obtain `test_case_id` from trusted scan/probe mapping, **not** from arbitrary target output. `attack_case_id` is a probe ID and is not `TC-00x`.
3. Pass trusted fixture and target authorization only from server-controlled records; do not accept them from an untrusted API request.
4. Invoke `validate_and_attest_backend_execution` with a secret, server-managed audit key (at least 32 random bytes), and persist the complete receipt together with the linked response evaluation/finding under a transaction.
5. Ensure `Response.id -> ResponseEvaluation.response_id` and `Response.id -> Finding.response_id` refer to the exact response being evaluated. Do not infer provenance from matching response text.
6. Restrict access to raw response content, planted fixture values, and the audit key. Redact logs and API-facing evidence.
7. Decide persistence shape/migration and retention policy with backend owner before changing DB models or shared schemas.

## Regression commands

```powershell
.\.venv-week2\Scripts\python.exe -m pytest security_validation/tests tests/test_week2_security_cases.py -v
```

Local contributor reported 118 passing tests for the adapter error fix. **The later remote traceability and finding changes are pending CI / full-suite execution**; do not treat this document as an E2E validation report.

## Out of scope / open dependencies

- Actual database persistence and migration for receipts: backend owner.
- Real judge verdict linkage and calibration: AI/ML owner.
- Tool-side attack/response provenance and execution error fields: attack-engine owner.
- Production proof for RAG/PII/system prompt scenarios: requires authorized targets, trusted fixtures, and independent source verification.
