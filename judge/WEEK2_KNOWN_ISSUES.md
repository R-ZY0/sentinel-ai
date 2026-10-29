# Sentinel AI — Week 2 AI/ML Judge Known Issues and Boundaries

1. **Advisory, not confirmed security findings.** Baseline output alone is insufficient to establish policy violation, attack success, severity, OWASP/CWE mapping, or a confirmed Finding. Trusted evidence and independent Security Validation are needed.
2. **No team-side automatic integration yet.** `BaselineRunner` provides a Python call only. No automatic FastAPI/Celery post-scan hook, PostgreSQL write, or REST endpoint is supplied by this deliverable. The lead's existing advisory scan review remains separate.
3. **Local TargetResponse adapter, not shared-contract authority.** `attack`, `expected_behavior`, and `response` must be available; any change to `contracts/` or backend schemas requires team agreement. Some real backend records may require context supplied by the caller.
4. **External runtime needs.** B1 requires Presidio and compatible spaCy language resources; B2/B3 require an available local Ollama endpoint and model. Runtime/network/model errors can interrupt the synchronous comparison; there is no retry, timeout policy, batch scheduler, or partial-results guarantee in the new runner.
5. **Duplicated inference cost.** The runner invokes B1/B2 directly, then B3 invokes B1/B2 internally again. The four-baseline comparison therefore repeats some analysis; production optimization needs deliberate design and regression tests.
6. **Five synthetic cases are too small for generalization.** B0/B1 matched 3/5 and B2/B3 matched 5/5 on these examples only. There is no representative benchmark, statistically meaningful performance estimate, or model drift evaluation.
7. **Uncalibrated confidence.** Confidence numbers are detector estimates, not directly comparable probabilities; do not rank vulnerabilities or set severity from them alone.
8. **No leak detection is not proof of safety.** A `NO_LEAK` response means that particular baseline did not detect evidence under its rules. Canary/Regex coverage depends on configured canaries/patterns; Presidio can report ordinary PII without confirmed exposure.
9. **Sensitive logs/outputs.** `signals` and evaluation reports may include excerpts or matched canary strings. The current examples are synthetic. Inspect any JSON reports before committing; never commit secrets or real personal data. Follow team's evidence retention controls.
10. **Response metadata is not authoritative validation.** Optional `status`, `timestamp`, and `latency` are type-checked by the local adapter but not authenticated or used to decide whether a response is eligible for review.
11. **Integration tests are not team E2E.** The 10 inherited scan-review tests are contract/fixture tests. A complete authorized attack-to-Finding deployment demonstration requires coordination among the other owners.

## Suggested next actions (team approval required)

- Agree on the exact shared `TargetResponse` mapping and source of `attack`/`expected_behavior` context.
- Decide where advisory baseline comparisons are stored/displayed and how evidence is protected.
- Verify authorized-target end-to-end integration and evidence-validation boundaries in a shared environment.
- Expand a versioned, realistic, synthetic test set and investigate false positives, costs, timeouts, and model versioning.
