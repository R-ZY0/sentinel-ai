from typing import Callable

from src.attack_run import AttackRun


class AttackRunner:
    def __init__(self, target: Callable[[str], str]):
        self.target = target

    def run(self, attack: AttackRun) -> AttackRun:
        try:
            attack.actual_response = self.target(attack.payload)
            attack.status = "completed"
            attack.execution_error = None
        except Exception as error:
            attack.actual_response = None
            attack.status = "failed"
            attack.execution_error = f"{type(error).__name__}: {error}"
            attack.evaluation_status = "not_evaluated"
            attack.passed = None
            attack.judge_reason = (
                "Execution failed; the attack response cannot be evaluated."
            )

        return attack
