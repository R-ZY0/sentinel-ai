
import asyncio

from pyrit.prompt_target import PromptTarget
from pyrit.executor.attack.single_turn.prompt_sending import PromptSendingAttack

from src.attack_run import AttackRun
from src.pyrit_adapter import pyrit_result_to_attack_run


class PyRITRunner:
    def __init__(
        self,
        target: PromptTarget,
        timeout_seconds: int = 60,
    ):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        self.target = target
        self.timeout_seconds = timeout_seconds

    async def run(self, attack: AttackRun) -> AttackRun:
        try:
            pyrit_attack = PromptSendingAttack(
                objective_target=self.target
            )

            result = await asyncio.wait_for(
                pyrit_attack.execute_async(
                    objective=attack.payload
                ),
                timeout=self.timeout_seconds,
            )

            return pyrit_result_to_attack_run(
                result=result,
                category=attack.category,
                target=attack.target,
                strategy=attack.strategy,
                expected_behavior=attack.expected_behavior,
                original_attack_id=attack.attack_id,
            )

        except asyncio.TimeoutError:
            error_message = (
                f"Attack timed out after {self.timeout_seconds} seconds."
            )

        except Exception as exc:
            error_message = f"{type(exc).__name__}: {exc}"

        return AttackRun(
            attack_id=attack.attack_id,
            category=attack.category,
            payload=attack.payload,
            target=attack.target,
            strategy=attack.strategy,
            expected_behavior=attack.expected_behavior,
            actual_response=None,
            status="failed",
            execution_error=error_message,
            evaluation_status="not_evaluated",
            passed=None,
            judge_reason=(
                "Execution failed; the attack response cannot be evaluated."
            ),
        )
