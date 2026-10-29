# Cyber #2 — Backend Integration Contract Review (Week 2)

**This is a read-only handoff to the Backend owner, not an approved production integration.** No changes to Backend, attack_engine, shared schema or the database have been made by Cyber #2.

## Current real Backend flow (source-reviewed)

- backend/app/scan_tasks.py: Celery run_scan passes authorized scan and target IDs to AttackRunner.
- backend/app/attack_runner.py: AttackEngine selects local probes; LocalTarget sends the request; CanaryRegexJudge and BasicJudge produce preliminary evaluations; persist_attack_run stores records.
- backend/app/attack_persistence.py: creates AttackAttempt, Response and optional Finding database rows in one transaction owned by the caller.
- backend/app/models.py: AttackAttempt has UUID id, UUID scan_id, nullable string attack_case_id, payload, category, status. Response has UUID id, UUID attack_attempt_id and content. Finding has UUID id, response_id, category, severity (string), status (string), evidence (text).

## Mapping to the existing Cyber #2 interface

| Backend record field | Cyber #2 expected field | Status |
| --- | --- | --- |
| AttackAttempt.id | attempt_id | read-only adapter supports string conversion of UUID |
| AttackAttempt.scan_id | scan_id | read-only adapter supports string conversion |
| AttackAttempt.attack_case_id | attack_id | required; cannot use nullable/empty values |
| AttackAttempt.payload | payload | required nonempty actual attack input |
| AttackAttempt.status | completed/failed state | completion required for positive confirmation |
| Response.attack_attempt_id | attempt_id correlation | must match actual selected attempt |
| Response.content | target_response.response | actual target reply, not judge summary |
| TC-001..TC-005 mapping | test_case_id | **Backend owner must approve the probe-to-test mapping**; SPL-001 and TC-001 are different IDs |
| Privileged independently planted fixture | trusted_fixture | **not represented in current Backend schema**; privileged server/test harness must provide it; never accept public caller flags |
| Canonical security/finding_schema.json Finding | database Finding | **incompatible structures**; needs reviewed persistence adapter owned by Backend |

## Important source-level privacy and trust findings

1. Current Backend attack_runner.py sets finding_evidence to the **literal synthetic canary** on a CanaryRegexJudge hit, and attack_persistence.py writes it into Finding.evidence. This exposes raw synthetic test values in a database record. The Backend owner should migrate to a redacted/hardened evidence representation, restrict access to stored responses, and determine data retention. Do **not** patch that outside Cyber #2 ownership.
2. Current canary is a hard-coded synthetic literal in Git-tracked backend/app/local_target.py. It is appropriate for simple offline regression tests, **not** a private production credential or proof of secret-impact severity. For an authorized independent security assessment, the trusted harness should generate an ephemeral non-repository fixture and verify it is placed in the actual running system message.
3. Backend heuristics and local canary pattern checks do not independently prove ACL, trusted origin or requester permissions. A confirmed Finding requires verification beyond the model response.
4. The canonical JSON Finding has severity as an object with CVSS v4.0 status and OWASP/CWE classification; the SQLAlchemy Finding model uses a severity string with no dedicated classification columns. Do not directly insert the canonical document into the SQLAlchemy table. Agree on a reviewed mapping or separate secured storage model.
5. The current AttackRunner owns retries, errors and transaction commits. Any integration hook must avoid inserting duplicate Findings and must preserve the original attempt/response IDs across replays. No shared database migration is authorized by this document.

## Backend owner questions / acceptance gates

- Identify the trusted fixture-provider component with target authorization, requester ACL and response provenance; verify it is not user-controlled.
- Agree on approved probe-to-TC mapping, stable IDs and error states.
- Design a read-only Cyber #2 invocation after persistence of AttackAttempt/Response; decide how to store validated evidence and optional HMAC receipt with confidential keys outside the repo.
- Decide how to store canonical OWASP/CWE classification and pending CVSS, without silently mapping unassessed scores into high severity.
- Remove or restrict raw-canary persistence and prevent public export of private model response content.
- Add owner-controlled end-to-end tests (scan -> persisted attempt -> response -> trusted validation -> Finding) and CI/PR review. Do not describe unit mocks as production tests.
- Confirm privilege boundary and authorized target scope before retesting.

## Current Cyber #2-owned code to reuse

- security_validation/src/adapter.py: from_backend_records(attempt, response, test_case_id=...)
- security_validation/src/pipeline.py: validate_backend_execution(..., trusted_fixture=..., finding_id=...)
- security_validation/src/traceability.py: validate_and_attest_backend_execution(..., audit_key=...)
- security_validation/src/triage.py: triage_finding(finding) with no automated CVSS score
- security_validation/src/jbb_canary_forensics.py: local redacted H-004 source/capture correlation; separate from actual TC-002 judgment

**Next owner action:** Review this mapping and the pending H-004 evidence gates. Until jointly approved, do not claim a real end-to-end integration, production Finding, CVSS score, or a production secret breach.
