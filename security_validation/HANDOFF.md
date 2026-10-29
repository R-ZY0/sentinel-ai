# Cyber #2 — Week 2 Component Handoff

**Branch:** \`feature/security-validation-week-02\` (based on \`release/week-01\`).

**Status:** Isolated component prepared; live integration pending.

## Added files

- \`security_validation/README.md\`, \`HANDOFF.md\`, \`requirements.txt\`.
- \`security_validation/__init__.py\` and \`security_validation/src/{__init__,validator,adapter,finding}.py\`.
- \`security_validation/tests/{__init__,test_validator}.py\`.
- \`security_validation/examples/{input.json,expected_output.json,run_example.py}\`.

The already-existing Week-2 scenario definitions in \`security/test_cases/\` remain the single source of scenario documents. The legacy Week-1 \`security/\` and \`eval/dataset/\` files remain in place for compatibility.

## Tests to run in the team environment

\`\`\`powershell
py -m pip install -r .\security_validation\requirements.txt
py -m unittest discover -s security_validation/tests -p 'test_*.py' -v
py -m security_validation.examples.run_example
py .\security\test_cases\validate_scenarios.py
py .\security\mappings\validate_mappings.py
\`\`\`

Record the actual test log and environment versions in the PR. Unit tests are **not** proof of real Ollama/RAG integration.

## Inputs / outputs / interface impact

- Input: real AttackRun/TargetResponse + **server-owned** authorization/provenance/fixture values.
- Output: conservative independent verdict and schema-compatible evidence; optional schema-valid Finding JSON.
- Example: \`examples/input.json\` -> \`examples/expected_output.json\` (synthetic).
- The adapter reads existing backend AttackAttempt/Response field names, but does not change backend models, API, database or shared contracts.

**No changes** to other members' code, shared contracts, taxonomy JSON or \`main\`.

## Remaining blockers before merge / end-to-end claims

- Team agreement on an authenticated server-side source of fixture values, ACL and provenance.
- Full Stack integration to persist Findings against the backend DB model.
- Live authorized target scans with RAG ACL, protected system prompt and PII record provenance.
- CI against the complete repository, review and PR acceptance.
- CTI enrichment/triage and production severity assessment are **not implemented**.

The component makes no assertion that an arbitrary real user can set trusted flags and prove a leak.
