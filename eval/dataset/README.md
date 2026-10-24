# JailbreakBench response validation

`raw/jailbreakbench/harmful-behaviors.csv` and `benign-behaviors.csv` contain **100
prompts per input class**, not 200 verified model-response classifications.

Run `python -m eval.dataset.process_jailbreakbench` to create 200 uniquely indexed
cases (`JBB-H-000..099` and `JBB-B-000..099`). The `behavior_class` field
indicates the prompt type. The source CSV's `Target` is retained as
`reference_target` for provenance: **it is not evidence of a model leak**.

`ground_truth=AMBIGUOUS` means that actual model output has not yet been observed
and adjudicated. The original converter incorrectly assigned `LEAK` to all
harmful prompts, `NO_LEAK` to all benign prompts, and duplicated all `JBB-0..99`
IDs. Neither classification is a legitimate response-level gold label.

## Capture real responses

Run `python -m eval.dataset.run_jailbreakbench_local --limit 20` in a Python
environment with `PYTHONPATH=backend:.`, Ollama running, and
`LOCAL_TARGET_MODE=protected`. For Docker, mount the repository read-only and a
separate writable volume at `/reports`; default report path is
`/reports/jbb_live_responses.jsonl`. The run uses the backend's canonical
protected `LocalTarget` request, records raw responses/errors, is resumable,
and interleaves harmful/benign prompts for a balanced smoke sample.

Use `--limit 200` for the full dataset after a successful smoke test. Existing
result records are preserved when resuming with matching model, mode, prompt
SHA256. Do not put private customer secrets in test targets or reports.

**Validation boundary:** Capturing all responses proves data coverage, **not**
attack success, model safety, accuracy, precision, recall, or F1. Review the
actual responses against a documented safety/helpfulness rubric, record
adjudicated per-response labels, and only then calculate meaningful metrics.
For harmful prompts, assess substantive harmful compliance vs safe refusal;
for benign prompts, assess appropriate help vs unnecessary refusal.

Unit contract: `python -m unittest discover -s tests -p test_jailbreakbench_dataset.py -v`.
