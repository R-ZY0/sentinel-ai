# Sentinel AI — Security Validation, Evidence & CTI Handoff

## 1. Role and Scope

**Role:** Cyber Security #2 — Security Validation, Evidence & CTI

This component supports security validation, canary-secret leakage analysis, evidence validation, security mappings, ground-truth evaluation, severity methodology, and security test-case documentation.

The reviewed files are located primarily in `security/` and `eval/dataset/`.

## 2. Delivered Files

### Security definitions and documentation
- `security/finding_schema.json`
- `security/ground_truth/ground_truth.json`
- `security/severity/cvss_methodology.md`
- `security/test_cases/TC-001-system-prompt-leakage.md`
- `security/test_cases/TC-002-canary-secret-leakage.md`
- `security/test_cases/TC-003-rag-document-leakage.md`
- `security/test_cases/TC-004-synthetic-pii-leakage.md`
- `security/test_cases/TC-005-synthetic-pii-leakage.md`

### Mapping and evidence utilities
- `security/mappings/owasp_mapping.json`
- `security/mappings/cwe_mapping.json`
- `security/mappings/validate_mappings.py`
- `security/evidence/build_canary_finding.py`
- `security/evidence/validate_canary_findings.py`
- `security/evidence/TC-001-result.json`

### Canary evaluation
- `eval/dataset/canary_analyzer.py`
- `eval/dataset/run_canary_tests.py`
- `eval/dataset/schema.json`
- `eval/dataset/README.md`
- `eval/dataset/synthetic/canary/canary_cases.jsonl`
- `eval/dataset/processed/canary_results.jsonl`
- `eval/dataset/processed/canary_analysis.jsonl`
- `eval/dataset/processed/canary_evidence_validation.jsonl`
- `eval/dataset/processed/tc002_finding.json`

This list reflects the files reviewed during handoff preparation and is not necessarily a complete repository inventory.

## 3. Validation Commands and Observed Results

Run the following commands from the repository root in PowerShell.

### OWASP/CWE mapping validation

```powershell
py .\security\mappings\validate_mappings.py
```

**Observed result:** PASSED. The validator reported OWASP and CWE mapping coverage for TC-001 through TC-005 and validated the TC-005 compound mapping.

### Canary evidence validation

```powershell
py .\security\evidence\validate_canary_findings.py
```

**Observed result:** 10 evaluation cases processed and saved to:

`eval/dataset/processed/canary_evidence_validation.jsonl`

The displayed classifications were:
- LEAK: 6 cases
- NO_LEAK: 1 case
- AMBIGUOUS: 3 cases

These classifications matched the displayed ground-truth labels for the reviewed cases.

### Canary test runner

```powershell
py .\eval\dataset\run_canary_tests.py
```

**Observed result:** 10 test cases loaded, 10 responses captured, and results saved to:

`eval/dataset/processed/canary_results.jsonl`

### Canary analyzer

```powershell
py .\eval\dataset\canary_analyzer.py
```

The existing `canary_analysis.jsonl` artifact was reviewed and contained 10 predictions matching the displayed ground-truth labels. A fresh analyzer execution was not confirmed as part of this review.

## 4. Inputs and Outputs

### Inputs
- Synthetic canary test cases.
- Target responses captured by the canary runner.
- Ground-truth labels for evaluation.
- Security finding definitions and OWASP/CWE mappings.

### Outputs
- `eval/dataset/processed/canary_results.jsonl`
- `eval/dataset/processed/canary_analysis.jsonl`
- `eval/dataset/processed/canary_evidence_validation.jsonl`
- `eval/dataset/processed/tc002_finding.json`

The exact interfaces with the platform, attack engine, AI/ML judge, and reporting layer still require confirmation against the team's approved contracts.

## 5. Dependencies and Environment

- Python 3.14.8 was available in the environment used for the reported runs.
- The reviewed canary analyzer uses Python standard-library modules including `base64`, `json`, and `pathlib`.
- Complete dependencies for all scripts have not been verified.
- No dedicated `requirements.txt` was found in the reviewed `security/` and `eval/` directories.

## 6. Known Gaps and Follow-up Items

- Confirm the current Git branch and pull-request status.
- Confirm alignment with the team's approved component structure and shared contracts.
- Add or identify a dedicated component-level test suite if required by the team.
- Add standardized example input/output fixtures if required by the team.
- Verify complete runtime dependencies.
- Confirm the implementation and integration status of CTI functionality.
- Run integration tests in the team's environment.
- Review the TC-005 test-case filename and content for consistency before changing either.

These items have not been represented as completed.

## 7. Security and Integration Notes

- Do not commit real secrets, API keys, personal data, or `.env` files.
- Use synthetic fixtures for controlled security evaluations.
- Do not change shared contracts without team review and approval.
- Keep AMBIGUOUS evidence distinct from confirmed leakage.
- Treat agreement with the current fixtures as evaluation evidence, not proof of general model accuracy or production readiness.

## 8. Handoff Status

**Status:** Documentation and initial validation evidence prepared.

Mapping validation, canary evidence validation, and canary response capture were run successfully in the reviewed local environment. Git branch/PR status, complete dependencies, CTI integration, and end-to-end integration readiness remain unverified.