from attack_engine.attack_library import AttackCase
from attack_engine.attack_run import AttackRun


def attack_case_to_attack_run(
    attack: AttackCase,
    target: str,
) -> AttackRun:
    return AttackRun(
        attack_id=attack.attack_id,
        category=attack.category,
        payload=attack.payload,
        target=target,
        strategy=attack.strategy,
        expected_behavior=attack.expected_behavior,
    )
