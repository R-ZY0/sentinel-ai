# Sentinel AI — AI/ML Judge Known Issues and Limitations

## Scope and status

The Week 1 Judge module is implemented and locally tested. This file records known limitations, deferred improvements, and integration tasks that have **not** been accepted as complete.

## Detection limitations

### Canary/Regex Judge

- Detects configured exact canary values, their Base64 encodings, and configured regular expressions.
- Does not comprehensively detect arbitrary secrets, paraphrases, transformations, or other encodings.
- `NO_LEAK` means no configured rule matched; it is not proof that the response is safe.
- Match evidence may contain the actual test canary or matched substring.

### Presidio Judge

- Recognizes configured PII entity types in English using Presidio and the installed language model.
- PII detection may have false positives and false negatives.
- Detecting PII is not sufficient by itself to establish unauthorized disclosure.
- Recognition depends on the configured entities, score threshold, language, and models.

### LLM Judge

- Requires a reachable Ollama service and the selected local model (`llama3.2:3b` by default).
- Responses may vary with model/runtime versions and evaluation context, even with temperature set to zero.
- Structured output validation constrains the JSON shape, but does not guarantee a correct security judgment.
- Prompt injection and adversarial inputs targeting the judge need additional robustness testing.
- Returned confidence values are not calibrated probabilities or vulnerability severity scores.

### Hybrid Judge

- Applies fixed decision rules combining Presidio and LLM outputs.
- A Presidio finding not confirmed as a clear leak by the LLM leads to `AMBIGUOUS`.
- The policy has not been validated on a large independent benchmark.
- Nested `signals` include component results and may expose sensitive response-derived evidence. Treat logs and database records accordingly.

## Integration limitations

- The Judge exposes Python classes; it does not currently provide a REST API endpoint.
- Shared API/schema approval with other component owners is pending.
- Backend and Attack Engine integration is not yet verified.
- Full scan orchestration and end-to-end scan verification are outside this module's demonstrated Week 1 behavior.
- Database persistence is not implemented by this Judge module; PostgreSQL proof must come from integration tests with the owning component.
- Docker Compose compatibility has not been verified by the Judge team.

## Reproducibility limitations

- `judge/requirements.txt` currently lists unpinned Python packages.
- spaCy `en_core_web_lg` must be installed separately.
- Ollama and the `llama3.2:3b` model must be available for LLM and Hybrid integration-style tests.
- Local Windows tests passing does not yet demonstrate that the module works in a clean shared environment.

## Deferred work

- Larger independent evaluation dataset and measured false-positive/false-negative rates
- Additional encodings and transformed-secret detection
- LLM prompt-injection robustness tests and confidence calibration
- Safe handling/redaction of sensitive evidence in logs and storage
- Team-approved interface contracts
- Backend/Attack Engine integration and full-scan testing
- Docker Compose and PostgreSQL persistence verification
- Release-level acceptance checks

## Week 1 handoff status

**Observed locally:** Judge implementations, evaluation fixtures, example input/output, and 16 passing automated tests.

**Still pending:** Current evaluation rerun, final documentation review, Pull Request creation/review, agreed shared interfaces, integration testing, and release acceptance.

Do not describe this module or the full platform as fully integrated or production-ready based solely on these local tests.
