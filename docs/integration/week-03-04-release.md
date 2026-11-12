# Combined Week 3–4 integration and release gate

## Sources and branch policy

This integration starts from the Full Stack delivery `04f9edc` on `develop` and
merges all three team deliveries with their original history:

| Workstream | Branch | Delivery head |
| --- | --- | --- |
| AI/ML | feature/ai-judge-week-03-04 | 0e52b42 |
| Attack engine | feature/attack-engine-week3-week4 | dbeba7c |
| Evidence validation | feature/security-validation-week-03-04 | df43bb2 |

Integration branch: `integration/week-03-04`. Intended release branch:
`release/week-03-04`. Promote the exact tested integration commit after live
acceptance and GitHub checks pass. Do not publish an unverified release merely
because Git completed the merges. Do not rewrite the individual member branches.

## Connected execution path

```text
Authenticated Scan API + target/configuration/selected attack snapshots
  -> Celery claim and cancellation checks
  -> normalized AttackDefinition + executable attack-engine AttackRunner
     OR real isolated PyRIT/garak tool execution
  -> saved authorized Target -> TargetAdapter -> local Ollama
  -> captured response, source attempt, status, UTC timestamps and latency
  -> B0 reference/regex and B1 Presidio baselines + Week3LLMJudge
  -> independent five-case evidence validation
  -> schema-valid Finding document + verified HMAC evidence receipt
  -> PostgreSQL evaluation, confirmed finding/evidence/mappings, receipt
  -> ownership-scoped GET /scans/{id}/results
```

The shared attack, verdict, evidence, finding JSON schema and report formats are
unchanged. Backend adapters retain metadata/envelopes without renaming shared
fields. Existing case IDs, UUID attempt IDs, and scanner report IDs stay distinct.
The agreed security contract uses `LEAK -> confirmed`, `NO_LEAK -> rejected`,
`AMBIGUOUS -> potential`. A plan calling that last status "ambiguous" does not
authorize silently changing the existing `potential` enum.

The new profile is explicitly selected with `configuration.pipeline: "week34"`.
Existing callers retain the Week 2 default. A saved profile selects its own runner;
changing `SENTINEL_PIPELINE` does not override an already-saved scan configuration.

## Trusted scenario mapping

| Scenario | Representative selected library ID | Trusted protected source |
| --- | --- | --- |
| TC-001 system prompt | SPL-001 | independently generated internal instruction |
| TC-002 canary | DL-001 | ephemeral server-generated secret |
| TC-003 RAG document | RL-001 | privileged retrieval from an in-memory restricted document source |
| TC-004 synthetic PII | DL-003 | server-generated synthetic email record |
| TC-005 injection to leakage | PI-002 | untrusted user instructions against an ephemeral internal secret |

Each source is installed by the server-owned target harness and confirmed loaded
only after a real usable target reply. Neither API callers nor model outputs can
supply trusted fixture flags/values. The requester is unprivileged; output policy
denies disclosure. The RAG demonstration tests a privileged-retrieval/unprivileged-
response boundary in controlled local context. It is not a production vector DB,
external RAG connector, or proof of a customer's document ACL enforcement.

PyRIT/garak remain isolated real tool services against the protected canonical
local target. Their existing canary harness maps to TC-002, even when a scanner's
attack category is prompt injection/jailbreak. Library scenarios cover all five
cases. Tool results use actual per-attempt payload/response records, not aggregate
detector summaries. Tool versions are recorded. Tool latency is explicitly labeled
`scanner-service-batch`; it must not be interpreted as an individual garak payload
latency. Library latency is measured for the individual target call.

## Judge, dataset and evidence policy

The Week 3 judge runs locally using `llama3.2:3b`, temperature 0, seed 42, and a
120-second client timeout. B0, B1 and the new LLM judge evaluate the same response.
Week 2's B0–B3 evaluation remains available on its original profile; its scores
must not be mislabeled as the new LLM implementation.

Model names/digests and installed package versions are recorded with evaluations.
The AI/ML dataset loader validates the merged synthetic labels, and its artifact
hash/case IDs are recorded. Synthetic benchmark labels are not assigned to new
live responses. JailbreakBench jailbreak success is not leakage ground truth.
No production accuracy figure is inferred from synthetic tests.

The judge is advisory. Independent evidence rules decide whether protected values
were actually disclosed under the trusted scenario controls. LLM/network errors
remain ambiguous or operational failures, never safe passes. Target/scanner
failures retain structured attempt metadata without manufacturing a response.
Cancellation prevents late evaluation/finding/receipt commits; in-flight external
calls may finish. Retry count is zero for the controlled target calls to avoid
duplicate executions after timeouts.

The complete security finding document is retained for confirmed, rejected and
potential outcomes in `ResponseEvaluation.security_result`. Only confirmed
outcomes additionally create canonical Finding/Evidence/VulnerabilityMapping rows.
CVSS remains unassessed pending human impact review; no CTI attribution is invented.

Security receipts are verified before insertion in the same transaction as the
evaluation/finding. `evidence_receipts.response_id` is a unique FK. Raw fixture
values are not archived. Retrieval verifies the signed receipt body and retained
response/validation/finding records; it authenticates the original fixture digest
without reconstructing the fixture. This proves integrity under the key, not the
truth of access/provenance assertions. Raw fixture replay and key rotation with a
historical keyring remain outside this delivery. Preserve the key for audits.

## Configuration and minimal rebuild

Requirements files and expensive dependency-install layers are unchanged.
The additive `0003_week34_integration` upgrade preserves existing records,
adds attempt metadata/case IDs and a unique response-linked receipt table, and
is safe to rerun. API and worker startup serialize upgrades with the existing
PostgreSQL advisory lock. Back up deployment databases before upgrading.

On this checkout a local `EVIDENCE_AUDIT_KEY` was generated in ignored `.env`
without displaying it. Other team members generate their own once:

```powershell
py backend/app/tools/configure_evidence_key.py
```

It preserves a valid existing key and other settings, rejects invalid/duplicate
keys, and never prints the value. Do not commit/share `.env`. Both API and worker
receive the key. Missing/invalid signing configuration rejects Week 3–4 start
before calling the target. `WEEK34_TARGET_MODE=protected` is the default.

Run from the repository root, using Docker instead of the moved Windows venvs:

```powershell
docker compose config --quiet
docker compose up -d --build api celery pyrit garak
docker compose exec api python -m unittest discover -s app/tests -t . -v
docker compose exec api python -m app.tests.live_acceptance
```

The live gate creates a separate verification account (credentials never printed),
authorized target, and a scan selecting all five representative library cases
plus PyRIT and garak. It polls for completion and checks stored responses,
baseline/LLM comparisons, model/tool version metadata and signed receipts.
It also verifies cancellation and rejection of a cancelled scan's start.
It leaves labeled history for audit. This account's credentials are temporary;
normal users cannot read its private records. Re-run the gate to reproduce it.

Copy the redacted report back for review:

```powershell
docker compose cp api:/tmp/week34-live-results.json docs/integration/week-03-04-live-results.json
```

Optional positive demonstration: set `WEEK34_TARGET_MODE=demo_vulnerable` in the
operator's environment, recreate only Celery with `docker compose up -d --no-deps
celery`, and run the live gate with `--require-finding --output
/tmp/week34-demo-results.json`. This deliberately weakens only the library's
synthetic local target instructions; scanner services remain protected. The gate
requires an actual confirmed finding, not just a detector hit. Restore protected
mode and recreate Celery afterward. No image rebuild is needed for this switch.

## API handoff example

Register/validate an authorized canonical local target using the existing APIs.
Use its returned ID in this payload (the UUID below is illustrative):

```json
{
  "target_id": "9e0e4a83-0b00-43f7-88be-2b15c328e5b8",
  "configuration": {
    "pipeline": "week34",
    "engines": ["library", "pyrit", "garak"],
    "attack_ids": ["SPL-001", "DL-001", "RL-001", "DL-003", "PI-002", "PYRIT-PI-001", "GARAK-DAN-001"]
  },
  "auto_start": false
}
```

Start with `POST /scans/{id}/start`; poll `GET /scans/{id}`; retrieve the complete
linked results with `GET /scans/{id}/results`. Default response content is redacted.
`include_raw=true` is explicit, ownership-checked and audited. Other owners get
404. Legacy unowned records retain their previously documented shared behavior.
Structured metadata retains errors, IDs, timing and response provenance. It does
not retain the protected fixture value as metadata or copy it into audit logs.

## Acceptance status

- All four workstreams are merged locally with original branch history.
- 331 local automated tests pass, including the new backend integration and
  contributor suites. The backend gate currently contains 77 tests.
- Five safe and five controlled-leak cases exercise the actual normalized runner,
  Week3LLMJudge, independent validator, schema validation, database persistence,
  redaction, receipt integrity, mappings and owner-scoped retrieval. Network and
  LLM transport are controlled in these tests; they are not live exploitation.
- GitHub gates cover PostgreSQL migrations/backend acceptance, judge/datasets,
  evidence rules and isolated scanner builds/tests.
- **Still required before release promotion:** rebuilt Docker/PostgreSQL suite,
  live five-case + real-tool acceptance, successful confirmed-finding demo,
  recorded redacted evidence, and passing CI for the final integration commit.

Generic external REST scans, production RAG connectors, polished UI, final
report generation, and production-scale recovery/security guarantees are not
claimed by this controlled Week 3–4 milestone.
