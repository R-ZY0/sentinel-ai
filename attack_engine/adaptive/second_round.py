"""One bounded, controller-requested follow-up against an authorized target.

No schema, database, judge, or Celery changes. The caller owns authorization,
persistence, attempt UUIDs, response mapping, and controller decisions.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import inspect

from attack_engine.attack_run import AttackRun
from attack_engine.attack_schema import AttackDefinition
from attack_engine.mutation import AttackVariant, MutationError, VariantGenerator
from attack_engine.normalized_attack_adapter import normalized_attack_to_attack_run


@dataclass(frozen=True)
class SecondRoundRequest:
    decision: str
    definition: AttackDefinition
    target_name: str
    authorized: bool
    history: tuple[AttackRun, ...]
    max_attempts: int = 2
    seed: int = 0

    def __post_init__(self):
        if self.decision not in {"ACCEPT", "SECOND_ROUND", "STOP"}:
            raise ValueError("Unsupported controller decision")
        if not self.target_name.strip():
            raise ValueError("target_name is required")
        if type(self.authorized) is not bool:
            raise TypeError("authorized must be boolean")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if not isinstance(self.history, tuple) or not all(isinstance(item, AttackRun) for item in self.history):
            raise TypeError("history must be a tuple of AttackRun values")


@dataclass(frozen=True)
class SecondRoundResult:
    status: str  # skipped | executed | execution_failed
    reason: str
    variant: AttackVariant | None = None
    attack_run: AttackRun | None = None


async def execute_second_round(request: SecondRoundRequest, runner) -> SecondRoundResult:
    """Perform at most one extra attempt, never retrying after an error.

    A caller must provide its complete history. This function does not
    independently validate ownership or persist state; `authorized` is a
    mandatory, server-verified precondition, never a user-supplied flag.
    """
    if not isinstance(request, SecondRoundRequest):
        raise TypeError("request must be SecondRoundRequest")
    if not request.authorized:
        return SecondRoundResult("skipped", "Target authorization not verified")
    if request.decision != "SECOND_ROUND":
        return SecondRoundResult("skipped", "Controller did not request another round")
    if not request.history:
        return SecondRoundResult("skipped", "A first attempt is required")
    if len(request.history) >= request.max_attempts:
        return SecondRoundResult("skipped", "Maximum attempt count reached")
    if any(item.target != request.target_name for item in request.history):
        return SecondRoundResult("skipped", "History belongs to a different target")
    if request.history[0].attack_id != request.definition.attack_id:
        return SecondRoundResult("skipped", "History does not match attack definition")
    if any(item.status != "completed" for item in request.history):
        return SecondRoundResult("skipped", "An execution failure cannot trigger another round")

    run_method = getattr(runner, "run", None)
    if not callable(run_method):
        raise TypeError("runner must provide run(AttackRun)")

    try:
        variant = VariantGenerator().generate(
            request.definition,
            seed=request.seed,
            count=1,
            used_payloads=[run.payload for run in request.history],
        )[0]
    except MutationError as error:
        return SecondRoundResult("skipped", str(error))

    # Existing adapter produces a new independent AttackRun; no shared change.
    run = normalized_attack_to_attack_run(variant, request.target_name)
    try:
        if inspect.iscoroutinefunction(run_method):
            result = await run_method(run)
        else:
            result = await asyncio.to_thread(run_method, run)
            if inspect.isawaitable(result):
                result = await result
        if not isinstance(result, AttackRun):
            raise TypeError("runner must return AttackRun")
        if result is not run:
            raise ValueError("runner returned a different AttackRun object")
        if result.attack_id != variant.attack_id or result.payload != variant.payload or result.target != request.target_name:
            raise ValueError("runner changed the variant identity or target")
        if result.status not in {"completed", "failed"}:
            raise ValueError("runner returned an invalid execution status")
    except Exception as error:
        run.status = "failed"
        run.actual_response = None
        run.execution_error = f"{type(error).__name__}: {error}"
        run.evaluation_status = "not_evaluated"
        run.passed = None
        run.judge_reason = "Execution failed; response not evaluated."
        return SecondRoundResult("execution_failed", run.execution_error, variant, run)

    if result.status == "failed":
        result.evaluation_status = "not_evaluated"
        result.passed = None
        return SecondRoundResult("execution_failed", result.execution_error or "Target execution failed", variant, result)

    # Execution success does not constitute a security finding or judge verdict.
    return SecondRoundResult("executed", "Second-round execution completed; evaluation pending", variant, result)
