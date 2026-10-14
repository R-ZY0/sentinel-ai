import uuid

from src.attack_library import ATTACK_LIBRARY
from src.attack_case_adapter import attack_case_to_attack_run
from src.pyrit_runner import PyRITRunner
from src.basic_judge import BasicJudge
from src.finding import Finding
from src.second_round import create_second_round_attack


async def run_attack_library(
    runner: PyRITRunner,
    target_name: str,
    finding_repository=None,
    second_round: bool = False,
):
    results = []
    judge = BasicJudge()

    for attack_case in ATTACK_LIBRARY:
        original = attack_case_to_attack_run(attack_case, target_name)
        attacks_to_run = [original]

        if second_round:
            attacks_to_run.append(create_second_round_attack(original))

        for attack in attacks_to_run:
            result = await runner.run(attack)

            if result.status == "failed":
                result.evaluation_status = "not_evaluated"
                result.passed = None

                if not result.judge_reason:
                    result.judge_reason = (
                        "Execution failed; the attack response "
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
                finding = Finding(
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
                finding_repository.save(finding)

            results.append(result)

    return results
