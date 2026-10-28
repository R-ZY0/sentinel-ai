# Week 2 — standalone baseline comparison (judge-owned)

This module is **advisory only**. It does not edit backend, contracts, scans,
findings, or database records. It compares the existing four judges:
B0 Canary/Regex, B1 Presidio, B2 LLM, B3 Hybrid.

## API

```python
import json
from judge.baselines import BaselineConfig, BaselineRunner

with open("judge/examples/week2_target_response.json", encoding="utf-8") as stream:
    target_response = json.load(stream)
runner = BaselineRunner(BaselineConfig(canaries=("SYNTH_CANARY_X1",)))
comparison = runner.evaluate(target_response)
print(comparison)
```

`evaluate` accepts a mapping with `response`, plus `attack` (or `prompt`)
and `expected_behavior` required by the LLM. These may instead be supplied
as keyword arguments for shared-style `TargetResponse` payloads. Optional
`attack_id` (or `case_id`), `status`, `timestamp`, and `latency` are recognized.
This is a **judge-local adapter**, not a claim that the shared schema is approved.

Output keys: `attack_id`, `advisory_only: true`, `baselines`, with B0-B3 each
serialized via the existing `JudgeVerdict.to_dict()` contract. There is no
combined official final Finding or severity. Do not treat `NO_LEAK` as proof
of safety or a PII match as confirmed unauthorized disclosure.

## Run tests without Ollama or Presidio services

```bat
python -m unittest judge.tests.test_week2_baselines -v
```

Tests inject stand-in judges for B1-B3 while exercising the real B0 logic.
For a full real-model run, install `judge/requirements.txt`, spaCy language
model, and start Ollama with the configured model; see `judge/README.md`.
The real B1/B2/B3 runtime and team E2E integration are separate acceptance
checks and must not be inferred from these offline tests.

## Security notes

Synthetic examples only. Existing B0 and B3 signals may contain matched
secret values or response-derived evidence. Treat output as sensitive and do
not log or persist it without the team's approved evidence-handling policy.
There are no network, database, or target calls by this adapter; B2/B3 may
call a configured Ollama host when executed with real judges.
