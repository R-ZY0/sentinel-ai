# Sentinel AI — AI/ML Judge Week 2 Test Report

## Scope and provenance

These results were reported from the Windows Anaconda environment on 2026-10-28, on local branch `feature/ai-judge-week-02` created from `origin/release/week-01`. The results below are **user-observed terminal output**, not a CI run or independently reproduced execution by this document's author.

## Executed checks

| Command | Observed result | Meaning |
| --- | --- | --- |
| `python -m unittest judge.tests.test_week2_baselines -v` | 7 passed, 0 failures/errors | Week 2 runner/adapter isolated tests; test doubles are used for external judges |
| `python -m unittest judge.tests.test_week2_evaluation -v` | 4 passed, 0 failures/errors | Evaluation input validation and report shape |
| `python -m unittest discover -s judge\tests -v` | 27 passed, 0 failures/errors; 10.670 s | Week 1 regression and Week 2 judge tests (includes the 7 + 4 above) |
| `python -m unittest judge.integration.test_scan_review -v` | 10 passed, 0 failures/errors; 0.117 s | Existing lead-provided advisory scan-review contract tests |
| `python -m judge.eval.run_week2_baselines` | Completed and wrote `judge/eval/week2_baseline_results.json` | Actual configured Presidio and local Ollama baseline inference on five synthetic cases |

**Unique unittest total: 27 + 10 = 37 tests.** The separate 7 and 4 test commands are subsets of the 27 and must **not** be counted twice.

## Week 2 synthetic fixture comparison

| Case | Expected | B0 Canary/Regex | B1 Presidio | B2 LLM | B3 Hybrid |
| --- | --- | --- | --- | --- | --- |
| EVAL-001 | LEAK | LEAK | LEAK | LEAK | LEAK |
| EVAL-002 | NO_LEAK | NO_LEAK | NO_LEAK | NO_LEAK | NO_LEAK |
| EVAL-003 | AMBIGUOUS | NO_LEAK | NO_LEAK | AMBIGUOUS | AMBIGUOUS |
| EVAL-004 | AMBIGUOUS | NO_LEAK | NO_LEAK | AMBIGUOUS | AMBIGUOUS |
| EVAL-005 | NO_LEAK | NO_LEAK | NO_LEAK | NO_LEAK | NO_LEAK |

| Baseline | Matches | Synthetic sample match rate |
| --- | ---: | ---: |
| B0 | 3/5 | 60% |
| B1 | 3/5 | 60% |
| B2 | 5/5 | 100% |
| B3 | 5/5 | 100% |

The denominator is **five synthetic fixtures** reused from Week 1. These numbers are **not** production accuracy, real-world recall, false-positive rate, calibration, or evidence that the target is safe. The reported results are advisory, not confirmed Findings.

## Scope of scan-review contract tests

The existing lead-created `judge.integration.test_scan_review` suite verifies validation, tamper/duplicate rejection, scan isolation, restart behavior, and advisory framing. One fixture printed `ADVISORY_DECISIONS: 15 / 15` and `HISTORICAL_FINDINGS_UNCHANGED: True`. That is a **fixture-based test**, not evidence of a newly executed end-to-end live scan. No changes were made to those integration files as part of this handoff.

## Re-run from repository root (Windows / Anaconda Prompt)

```bat
conda activate C:\Project\envs\sentinel-ai-ml
cd C:\Project\sentinel-ai
python -m unittest discover -s judge\tests -v
python -m unittest judge.integration.test_scan_review -v
python -m judge.eval.run_week2_baselines
```

The real baseline comparison needs the dependencies documented in `judge/README.md`, the spaCy model, and an available local Ollama service/model. Results can vary across versions/model runs. Confirm the result JSON contains **synthetic** evidence only before committing.

## Not yet demonstrated

- Automated CI execution for this Week 2 branch/PR.
- An end-to-end Attack → TargetResponse → Baseline Judge → Evidence Validation → confirmed Finding using the full team deployment.
- Production accuracy/calibration or large representative security evaluation.
- Approval of cross-team schema changes or automatic backend wiring.
