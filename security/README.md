# Sentinel AI — Security Validation, Evidence & CTI

## 1. Overview

This component supports the security validation layer of Sentinel AI. It contains security finding definitions, ground-truth fixtures, OWASP/CWE mappings, severity methodology, test-case documentation, and evidence-validation utilities.

The current implementation and evaluation scripts are organized across `security/` and `eval/dataset/`.

## 2. Responsibilities

- Validate security findings against the defined finding schema.
- Maintain ground-truth fixtures for canary secrets, synthetic PII, and synthetic internal data.
- Map security test cases to OWASP LLM risks and CWE classifications.
- Analyze canary-secret leakage in target responses.
- Validate evidence and finding classifications against evaluation ground truth.
- Document severity assessment methodology and security test cases.

**CTI status:** Threat-intelligence enrichment and integration with external intelligence sources have not been verified as implemented in the current reviewed files. This remains to be documented and confirmed.

## 3. Current File Structure

```text
security/
├── finding_schema.json
├── ground_truth/
│   └── ground_truth.json
├── mappings/
│   ├── cwe_mapping.json
│   ├── owasp_mapping.json
│   └── validate_mappings.py
├── evidence/
│   ├── build_canary_finding.py
│   ├── validate_canary_findings.py
│   └── TC-001-result.json
├── severity/
│   └── cvss_methodology.md
└── test_cases/
    ├── TC-001-system-prompt-leakage.md
    ├── TC-002-canary-secret-leakage.md
    ├── TC-003-rag-document-leakage.md
    ├── TC-004-synthetic-pii-leakage.md
    └── TC-005-synthetic-pii-leakage.md

eval/dataset/
├── canary_analyzer.py
├── run_canary_tests.py
├── schema.json
├── README.md
├── synthetic/
│   └── canary/
│       └── canary_cases.jsonl
└── processed/
    ├── canary_results.jsonl
    ├── canary_analysis.jsonl
    ├── canary_evidence_validation.jsonl
    └── tc002_finding.json
```

The structure above reflects the files identified during the handoff review. Other files may exist in the repository but are not listed here.

## 4. Requirements and Dependencies

- Python: `3.14.8` was available in the environment used for the reported runs.
- The reviewed canary analyzer imports Python standard-library modules: `base64`, `json`, and `pathlib`.
- The complete dependency requirements for all scripts have not yet been verified.
- No dedicated `requirements.txt` was found under the reviewed `security/` and `eval/` directories.

## 5. How to Run

Run these commands from the repository root.

### Validate OWASP and CWE mappings

```powershell
py .\security\mappings\validate_mappings.py
```

### Run canary evaluation

```powershell
py .\eval\dataset\run_canary_tests.py
```

### Analyze canary responses

```powershell
py .\eval\dataset\canary_analyzer.py
```

### Validate canary findings and evidence

```powershell
py .\security\evidence\validate_canary_findings.py
```

## 6. Inputs and Outputs

### Inputs

- Security test cases and synthetic canary fixtures.
- Target responses produced by the canary test runner.
- Ground-truth labels used to evaluate classifications.
- Finding data and security mappings.

### Outputs

The reviewed scripts generate or use the following artifacts:

- `eval/dataset/processed/canary_results.jsonl`
- `eval/dataset/processed/canary_analysis.jsonl`
- `eval/dataset/processed/canary_evidence_validation.jsonl`
- `eval/dataset/processed/tc002_finding.json`

The exact interface between this component and the platform, attack engine, AI/ML judge, and reporting layer still needs to be confirmed against the shared contracts.

## 7. Validation Results

The following results were observed during the current review:

| Check | Observed result |
|---|---|
| OWASP/CWE mapping validation | PASSED |
| Mapping coverage for TC-001 through TC-005 | Present according to the validator |
| TC-005 compound mapping | Validated by the mapping script |
| Canary evidence validation | 10 cases processed |
| Canary test runner | 10 responses captured |
| Canary analysis | 10 predictions matched the displayed ground-truth labels |

These results apply to the reviewed scripts and the current evaluation cases. They do not establish general model accuracy, confidence calibration, or end-to-end integration readiness.

## 8. Known Gaps

- A dedicated component-level README and handoff document are being prepared.
- A dedicated `tests/` directory and standalone test suite were not found in the reviewed paths.
- Standardized `examples/input.json` and `examples/expected_output.json` files were not found.
- Full dependency requirements need to be confirmed.
- Shared input/output contracts need to be checked against the team’s approved contracts.
- CTI functionality and its integration status need confirmation.
- Branch status, pull-request status, and integration-test results have not been verified in this review.

## 9. Security Notes

- Do not commit real secrets, personal data, API keys, or `.env` files.
- Use synthetic fixtures for controlled security evaluations.
- Preserve the shared contracts unless changes have been reviewed and approved by the team.
- Treat ambiguous evidence separately from confirmed leakage.
- Report test results exactly as observed and distinguish fixture agreement from general detection performance.
