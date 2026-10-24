# Sentinel AI — AI/ML Judge Test Report

## Scope

This report covers the Week 1 **Judge module** only. It does not certify the full Sentinel AI platform, Docker Compose deployment, scan orchestration, or PostgreSQL persistence.

Implemented and tested components:

- `JudgeVerdict` and the `Verdict` enum
- Canary/Regex Judge
- Presidio Judge
- LLM Judge using local Ollama
- Hybrid Judge
- Example input/output fixture

## Local test environment

- OS: Windows (Anaconda Prompt)
- Python: 3.11
- Conda environment: `sentinel-ai-ml`
- LLM runtime: Ollama, model `llama3.2:3b`
- PII runtime: Microsoft Presidio with spaCy model `en_core_web_lg`

The local test environment is not equivalent to a clean container or production environment.

## Automated test evidence

From the repository root:

```bat
python -m unittest discover -s judge\tests -v
```

**Latest user-observed result (October 22, 2026):**

```text
Ran 16 tests in 20.125s

OK
```

| Test area | Passing tests |
| --- | ---: |
| Canary/Regex | 4 |
| Presidio | 3 |
| LLM | 3 |
| Hybrid | 5 |
| Example fixture | 1 |
| **Total** | **16** |

All 16 tests passed in the reported local run. Tests calling the real local model depend on Ollama availability; they are not all isolated unit tests.

## Input/output fixture verification

Files:

- `judge/examples/input.json`
- `judge/examples/expected_output.json`
- `judge/tests/test_examples.py`

The fixture passes the configured canary and target response to `CanaryRegexJudge`, serializes the `JudgeVerdict` using `.to_dict()`, and compares the complete result against the expected JSON.

Recorded manual check: `EXAMPLE TEST PASSED`. The fixture comparison is also included in the 16-test run.

**Scope note:** The fixture exercises the Canary/Regex Judge, not a full end-to-end scan or database write.

## Week 1 evaluation sample

The evaluation runner and data already exist:

```bat
python -m judge.eval.run_evaluation
```

The **previously recorded** five-case synthetic evaluation produced:

| Judge | Matches against expected labels |
| --- | ---: |
| Canary/Regex | 3/5 |
| Presidio | 3/5 |
| LLM | 5/5 |
| Hybrid | 5/5 |

These are historical results from a five-case sanity sample, **not** verified results of a fresh rerun on the current date and **not** estimates of real-world detection accuracy. Rerun the evaluation and inspect `judge/eval/evaluation_results.json` before claiming updated results in the Pull Request.

## Pending verification

- Cross-team approval of shared interfaces or schemas
- Backend and Attack Engine integration
- Docker Compose startup and health checks
- Full scan execution across components
- End-to-end/integration test results
- Evidence that scan results are stored in PostgreSQL
- Reproducibility in a clean project environment

## Conclusion

The Week 1 Judge module passed **16/16 local automated tests** in the latest observed run and its Canary/Regex example matched the expected output. The module can be submitted for code review, subject to documentation review and a current evaluation rerun. **Integration acceptance and production readiness remain pending.**
