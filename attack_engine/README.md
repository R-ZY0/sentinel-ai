# Attack Engine

## Overview

The Attack Engine is part of the Sentinel AI security testing project.
It provides attack definitions, normalized attack-library execution,
optional Garak/PyRIT integrations, heuristic response evaluation, and
potential Finding creation for review.

Use it only against systems that you own or are explicitly authorized to test.

## Attack Categories

- Prompt Injection
- System Prompt Leakage
- Data Leakage
- RAG Leakage
- Jailbreak

## Week 3 — Attack Execution

### Execution models

- `attack_run.py`: AttackRun execution/result data model.
- `attack_runner.py`: synchronous callable-target runner with timeout,
  bounded retries for configured exceptions, and duplicate-call protection.
- `normalized_attack_runner.py`: asynchronous library orchestration entry
  point. It supports synchronous runners by executing them in a worker
  thread, and asynchronous runners by awaiting them.
- `execution_contract.py`: exports AttackRun data with scan, target, and
  execution identifiers.
- `backend_contract.py`: maps attack-run data to the existing backend
  record contract. It does not create database attempt records.

### Optional tool adapters

- `pyrit_runner.py` and `pyrit_adapter.py`: PyRIT execution and result mapping.
- `garak_runner.py`: invokes Garak and processes its report.
- `garak_execution_bridge.py` and `garak_report_adapter.py`: Garak
  integration helpers.

Garak report execution is an aggregate scanner workflow. It must not be
assumed to provide an individual target response for every normalized
payload.

PyRIT and Garak are optional dependencies and are not required for the
normalized-library unit tests.

## Week 4 — Normalized Attack Library

- `attack_schema.py`: defines and validates `AttackDefinition`.
- `attack_registry.py`: indexes attack definitions by stable attack ID
  and category.
- `normalized_attack_library.py`: contains the normalized seed library.
- `normalized_attack_adapter.py`: converts normalized definitions into
  AttackRun objects.
- `attack_mutator.py`: creates a deterministic contextual-wrapper
  mutation without modifying the original definition.
- `test_attack_schema.py`, `test_attack_registry.py`, and
  `test_normalized_attack_library.py`: schema, registry, and library tests.

Each normalized attack definition contains:

- `attack_id`
- `category`
- `goal`
- `strategy`
- `payload`
- `expected_behavior`
- `mutation_strategy`

The schema also records whether mutation is supported and an optional
OWASP mapping. An OWASP mapping is left unset when a mapping has not been
verified against the agreed project taxonomy/version.

### Mutation limitations

The current mutation implementation adds a deterministic contextual
wrapper around the original payload. It does not perform semantic
paraphrasing, model-generated rewriting, or adversarial optimization.
The original attack definition is not modified.

The `second_round=True` option executes the original and its deterministic
mutated variant. Mutation support and strategy metadata describe this
limited implementation; they do not imply a more advanced mutation engine.

## Execution and evaluation

`run_normalized_attack_library(runner, target_name, ...)` accepts a runner
with a callable `run(attack)` method.

- Asynchronous `run` methods are awaited.
- Synchronous `run` methods execute in a worker thread.
- The runner must return an `AttackRun`.
- `second_round=True` requests a second execution using the contextual
  mutation for each library definition.

`BasicJudge` is heuristic. Its `pass`, `fail`, and `not_evaluated`
results are not a substitute for security validation or manual review.

- A `fail` is a potential issue requiring verification.
- `not_evaluated` does not prove that the target is secure.
- Execution failures are not judged as successful security attacks.
- A `PWNED` marker alone does not prove that a higher-priority instruction
  was overridden.
- Data Leakage and RAG Leakage require known sensitive test data and
  expected results for reliable verification.

When a `finding_repository` is supplied, the normalized runner saves a
Finding when the judge returns `fail`. The Finding is a potential issue
for review, not a confirmed vulnerability.

## Identifiers and backend contract

- `AttackRun.attack_id` identifies an attack definition, such as `PI-001`.
- The backend `AttackAttempt.id` identifies a database execution attempt.
- These identifiers are not interchangeable.
- `execution_id` in the export contract is not a substitute for a real
  backend `AttackAttempt.id`.
- The Attack Engine must not invent a backend attempt ID.
- Persistence of attack-definition identity across the backend database
  boundary requires an agreed team contract.
- Final shared contract approval and live backend integration remain
  subject to team review.

## Dependencies

Install the shared Attack Engine dependencies from the repository root:

    .\.venv-w34-audit\Scripts\python.exe -m pip install -r .\attack_engine\requirements.txt

Garak and PyRIT must be installed in separate virtual environments using
the supplied requirement files. Do not install both optional integrations
into the same environment unless their dependency compatibility has
been verified.

    python -m venv .venv-garak
    python -m venv .venv-pyrit

    .venv-garak\Scripts\python.exe -m pip install -r attack_engine\requirements-garak.txt
    .venv-pyrit\Scripts\python.exe -m pip install -r attack_engine\requirements-pyrit.txt

These environments must not be committed to Git.

## Tests

Run the focused normalized-library and runner tests:

    .\.venv-w34-audit\Scripts\python.exe -m pytest -q `
        attack_engine\test_attack_runner.py `
        attack_engine\test_attack_schema.py `
        attack_engine\test_attack_registry.py `
        attack_engine\test_normalized_attack_library.py `
        attack_engine\test_normalized_execution.py `
        attack_engine\test_normalized_runner_compatibility.py

Run the broader Attack Engine regression suite using the project's
available dependencies and configured import paths.

A full `pytest attack_engine` collection may require optional PyRIT/Garak
packages and backend import configuration. Collection errors caused by
missing optional packages or backend paths are environment/setup errors;
they do not represent failed test assertions.

Component unit tests are not equivalent to live PyRIT/Garak tests,
database tests, or a Docker-based end-to-end integration test.

## Examples

The JSON files in `examples/` are illustrative only. The current
implementation does not automatically load `input.json`, and
`expected_output.json` is not actual execution output.

## Validation limits

- Live PyRIT and Garak execution must be validated in their respective
  isolated environments.
- Backend persistence and database attempt-ID integration require the
  agreed shared contract and backend integration tests.
- Timeout behavior against real target services requires separate
  integration verification.
- Heuristic findings require manual review.

## Combined backend integration

Backend modules now live under app.services, app.tasks, and app.tools; backend tests are in backend/app/tests. Run the combined backend suite inside Docker with python -m unittest discover -s app/tests -t . -v.
