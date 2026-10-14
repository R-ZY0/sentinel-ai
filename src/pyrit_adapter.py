
from pyrit.executor.attack.single_turn.prompt_sending import AttackResult

from src.attack_run import AttackRun


def pyrit_result_to_attack_run(
    result: AttackResult,
    category: str,
    target: str,
    strategy: str,
    expected_behavior: str,
    original_attack_id: str | None = None,
    mutation_strategy: str | None = None,
) -> AttackRun:
    actual_response = None

    if result.last_response is not None:
        actual_response = result.last_response.original_value

    is_error = result.outcome.value == "error"

    execution_error = None
    if is_error:
        execution_error = (
            result.error_message
            or result.outcome_reason
            or f"PyRIT execution failed with outcome: {result.outcome.value}"
        )

    return AttackRun(
        attack_id=original_attack_id or result.attack_result_id,
        category=category,
        payload=result.objective,
        target=target,
        strategy=strategy,
        expected_behavior=expected_behavior,
        actual_response=actual_response,
        mutation_strategy=mutation_strategy,
        status="failed" if is_error else "completed",
        execution_error=execution_error,
        evaluation_status="not_evaluated" if is_error else "pending",
        passed=None,
        judge_reason=(
            "Execution failed; the attack response cannot be evaluated."
            if is_error
            else None
        ),
    )
