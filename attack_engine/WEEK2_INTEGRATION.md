# Sentinel AI - Cyber #1 - Week 2 Integration

## Scope

Integrate garak and PyRIT with the existing Attack Engine,
normalize execution outputs, preserve AttackRun information,
and validate execution on an authorized local target.

Original Week 2 development base: release/week-01, commit 4b9cef7.
Original working branch: feature/attack-engine-week-02.

Final integration base: team/develop, commit c6f99f5.
Delivery branch: feature/attack-engine-week-02-delivery.
Week 1 release is an ancestor of the tested develop base.

## Verified Environment

- Python: 3.14.4
- garak: 0.17.0
- pyrit: 1.1.0
- Ollama model: llama3.2:3b
- Target: local Ollama, protected mode
- No external target was tested.

## Existing Attack Library

15 attack cases, three in each category:

- Prompt Injection: PI-001 through PI-003
- System Prompt Leakage: SPL-001 through SPL-003
- Data Leakage: DL-001 through DL-003
- RAG Leakage: RL-001 through RL-003
- Jailbreak: JB-001 through JB-003

These are Sentinel attack cases, not 15 verified garak probes.

## Initial Probe Mapping

| Category | Candidate or tested probe | Evidence status |
| --- | --- | --- |
| Prompt Injection | garak.probes.promptinject | Module found; classes unresolved |
| System Prompt Leakage | sysprompt_extraction.SystemPromptExtraction | Static discovery only |
| Data Leakage | apikey.GetKey / apikey.CompleteKey | Static discovery only |
| RAG Leakage | latentinjection / web_injection | Candidates only; RAG leakage not verified |
| Jailbreak | dan.Dan_11_0 | Live local execution verified |

PyRIT PI-001 was also executed successfully against
the local protected Ollama target.

## Recorded Test Results

- Release baseline: 67 tests passed, zero failures.
- PyRIT local smoke test: completed, no execution error.
- garak local smoke test: completed, no execution error.
- Repeatability: PyRIT 2/2 and garak 2/2 completed.
- garak report audit: two evaluated samples, one detector hit,
  and one pass in the audited initial report.

A detector hit is not a confirmed vulnerability.
Security evaluation remains pending for live smoke tests.

## Output Normalization

- attack_case_to_attack_run preserves attack ID and category.
- pyrit_result_to_attack_run creates an AttackRun representation.
- Execution failures must not be treated as security findings.
- garak aggregate results are not individual attack verdicts.

## Shared Contract Caveat

The local AttackRun dataclass does not directly expose
scan_id and target_id. Integration contracts and persistence
mapping must be approved with the team.

No shared contract is changed by this deliverable.

## Remaining Week 2 Work

- Verify selected garak probe classes and suitability.
- Validate initial probes for all applicable categories.
- Verify RAG leakage on an authorized synthetic RAG target.
- Review normalized execution output and TargetResponse mapping.
- Re-run tests after any implementation changes.
- Agree on final shared interfaces with the integration team.
- Record final evidence and submit a reviewed pull request.

## Safety

Authorized local testing only. No real secrets, production
targets, or personal information are required.

## Week 2 Synthetic Garak Integration Results

The following results were obtained against authorized local Ollama
using fictional system instructions and synthetic canary strings.

- Garak SystemPromptExtraction generated a two-turn conversation:
  system followed by user.
- The original Garak REST generator uses the last message text only.
  The separate conversation adapter preserves both roles.
- Local HTTP transport uses 127.0.0.1:11434, disables environment
  proxy settings, and does not follow HTTP redirects.
- A live generated probe reached llama3.2:3b successfully.
- An exact synthetic canary appeared in the observed response.
  This is a preliminary observation, not an approved Finding.
- The synthetic execution bridge stored a nonempty response in
  AttackRun with status=completed and evaluation_status=pending.
- 93 local regression tests passed before the bridge commit.

Limitations:

- This execution path is separate from the full garak CLI runner.
- No JudgeVerdict or final security Finding was created.
- No database persistence or shared contract changes were made.
- Full team end-to-end integration remains unverified.
- RAG leakage requires an authorized synthetic RAG target.

## Verified Garak CLI Report Integration

The official Garak CLI was executed against an authorized local
Ollama target in protected mode using garak 0.17.0.

Verified configuration:

- Model: llama3.2:3b
- Endpoint: http://127.0.0.1:11434/api/chat
- Probe: probes.dan.Dan_11_0
- Attack ID: GARAK-DAN-001
- Aggregate execution status: completed
- Aggregate evaluation status: pending
- CLI report: JSONL and HTML generated successfully
- Scanner summary: 0 detector hits, 2 passes, 2 evaluated samples

The JSONL report contains two attempt records for one logical
attempt UUID: ATTEMPT_STARTED (1) and ATTEMPT_COMPLETE (2).

The local garak_report_adapter.py reads completed attempt records,
deduplicates lifecycle entries by UUID, and preserves the final
model response in a local AttackRun object.

Verification:

- Five report-adapter unit tests passed.
- Real CLI report normalization passed.
- Full local regression: 98 tests passed.
- No JudgeVerdict or Finding was generated automatically.

Integration limitations:

- The existing Garak CLI runner produces aggregate scanner results.
- The per-attempt report adapter is available separately; it is
  not yet automatically invoked by the CLI runner.
- Garak SystemPromptExtraction was live-tested through a separate
  synthetic conversation transport, not through this CLI path.
- Shared contract approval and full team end-to-end integration
  remain team-level tasks.
