# Week 6 — bounded second-round handoff

An opt-in, single-step execution boundary between the adaptive controller and
the existing Attack Engine. It accepts a previously saved first `AttackRun`,
the canonical `AttackDefinition`, the controller decision, full attempt history,
an already authorized target name, and a runner with `run(AttackRun)`.

```python
from attack_engine.adaptive import SecondRoundRequest, execute_second_round

request = SecondRoundRequest(
    decision="SECOND_ROUND", definition=definition,
    target_name="authorized-local", authorized=True,
    history=(first_attack_run,), max_attempts=2, seed=42,
)
result = await execute_second_round(request, existing_runner)
```

`SecondRoundResult.status` is `skipped`, `executed`, or `execution_failed`.
On execution, it carries the `AttackVariant` and an existing-contract
`AttackRun` with target output and execution status. It does not claim a
Judge verdict or confirmed finding. On failure evaluation is `not_evaluated`.

The function performs **at most one call**; retry policies remain controlled
by the provided runner. Use a runner configured with `max_retries=0` for the
authorized test pipeline. A timed-out threaded target may continue executing;
the caller must account for that before scheduling new attempts.

Safety: the integration owner must derive `authorized=True` from trusted,
server-controlled authorization checks, never directly from the request body.
Targets and history must match; a failed previous attempt cannot trigger a
second round; attempt count must be bounded (1–10). The caller must provide
the **complete persisted attempt history** to enable deduplication and limits.
Concurrent controller tasks must serialize check-and-claim of the attempt
budget in the database; this stateless module cannot prevent two workers
from executing simultaneously with the same stale history snapshot.

The controller owns ACCEPT/STOP/SECOND_ROUND decisions. This component does
not create UUID attempt records, persist findings, call the Judge, or validate
evidence. Integration requires Omar to map these results into API/Celery,
backend attempt IDs, TargetResponse, and security review workflows without
changing shared contracts unilaterally.

From the repository root:

```powershell
python -m pytest attack_engine/test_week6_second_round.py -q
```

Dependencies: Python standard library, existing Attack Engine and Week 5
mutation module. Network/LLM service is not required for local unit tests.
