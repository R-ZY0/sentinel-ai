"""Execution entry point for the normalized attack library."""

import asyncio
import inspect
import uuid

from attack_engine.attack_mutator import mutate_attack_definition
from attack_engine.attack_run import AttackRun
from attack_engine.basic_judge import BasicJudge
from attack_engine.finding import Finding
from attack_engine.normalized_attack_adapter import (
    normalized_attack_to_attack_run,
)
from attack_engine.normalized_attack_library import NORMALIZED_ATTACK_LIBRARY


async def _execute_with_runner(runner, attack):
    """Execute one attack using either a synchronous or asynchronous runner."""
    run_method = getattr(runner, "run", None)
    if not callable(run_method):
        raise TypeError("runner must expose a callable run(attack) method.")

    if inspect.iscoroutinefunction(run_method):
        result = await run_method(attack)
    else:
        result = await asyncio.to_thread(run_method, attack)
        if inspect.isawaitable(result):
            result = await result

    if not isinstance(result, AttackRun):
        raise TypeError(
            "The attack runner must return an AttackRun instance."
        )

    return result


async def run_normalized_attack_library(
    runner,
    target_name,
    finding_repository=None,
    second_round=False,
):
    """Execute normalized attacks with sync or async runners.

    Synchronous runners execute in a worker thread so they do not block
    the caller's asyncio event loop. Async runners are awaited directly.
    """
    if not callable(getattr(runner, "run", None)):
        raise TypeError("runner must expose a callable run(attack) method.")

    results = []
    judge = BasicJudge()

    for definition in NORMALIZED_ATTACK_LIBRARY:
        original = normalized_attack_to_attack_run(definition, target_name)
        attacks_to_run = [original]

        if second_round:
            mutated_definition = mutate_attack_definition(definition)
            attacks_to_run.append(
                normalized_attack_to_attack_run(
                    mutated_definition,
                    target_name,
                )
            )

        for attack in attacks_to_run:
            result = await _execute_with_runner(runner, attack)

            if result.status != "completed":
                result.evaluation_status = "not_evaluated"
                result.passed = None
                if not result.judge_reason:
                    result.judge_reason = (
                        "Execution did not complete; the attack response "
                        "cannot be evaluated."
                    )
            else:
                evaluation_status, reason, passed = judge.evaluate(result)
                result.evaluation_status = evaluation_status
                result.passed = passed
                result.judge_reason = reason

            if (
                finding_repository is not None
                and result.evaluation_status == "fail"
            ):
                finding_repository.save(
                    Finding(
                        finding_id=f"finding-{uuid.uuid4().hex}",
                        attack_id=result.attack_id,
                        category=result.category,
                        title=f"Potential {result.category} issue detected",
                        severity="Medium",
                        description=(
                            "The BasicJudge detected a possible security issue. "
                            "This heuristic result requires manual verification."
                        ),
                        evidence=result.actual_response,
                        remediation=(
                            "Review the attack payload and model response. "
                            "Verify the suspected issue and apply appropriate "
                            "security controls if confirmed."
                        ),
                        timestamp=result.timestamp,
                    )
                )

            results.append(result)

    return results
