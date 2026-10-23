# Attack Engine

## Overview

The Attack Engine is part of the Sentinel AI security testing project.

It executes authorized AI security tests, evaluates responses using heuristic rules, and records potential findings for review.

## Attack Categories

- Prompt Injection
- System Prompt Leakage
- Data Leakage
- RAG Leakage
- Jailbreak

## Main Components

- `attack_run.py`: Attack run data model.
- `attack_library.py`: Predefined attack cases.
- `attack_case_adapter.py`: Converts attack cases into attack runs.
- `pyrit_runner.py`: Executes attacks using PyRIT.
- `garak_runner.py`: Runs Garak and processes its reports.
- `basic_judge.py`: Evaluates responses using heuristic rules.
- `attack_library_runner.py`: Runs attack cases and evaluates responses.
- `second_round.py`: Supports mutated second-round attacks.

## Evaluation and Findings

- `pass`, `fail`, `pending`, and `not_evaluated` represent evaluation states.
- A `fail` result is a potential issue requiring manual review, not automatically a confirmed vulnerability.
- `not_evaluated` does not prove the target is secure.
- Execution errors must not be treated as confirmed security findings.

## Dependencies

Install the component dependencies from the repository root:

    .\.venv\Scripts\python.exe -m pip install -r .\attack_engine\requirements.txt

## Examples

The JSON files in `examples/` are illustrative only. The current implementation does not automatically load `input.json`, and `expected_output.json` is not actual execution output.

## Tests

Run Attack Engine component tests:

    .\.venv\Scripts\python.exe -m pytest .\attack_engine -v

Run backend pipeline tests:

    .\.venv\Scripts\python.exe -m pytest .\backend\app\test_pipeline.py -v

## Authorized Use

Test only systems you own or have explicit authorization to assess.
