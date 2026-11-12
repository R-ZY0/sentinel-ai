"""Adapters for normalized attack definitions."""

from attack_engine.attack_run import AttackRun


def normalized_attack_to_attack_run(definition, target):
    """Convert a normalized AttackDefinition into an independent AttackRun."""
    return AttackRun(
        attack_id=definition.attack_id,
        category=definition.category,
        payload=definition.payload,
        target=target,
        strategy=definition.strategy,
        expected_behavior=definition.expected_behavior,
        mutation_strategy=definition.mutation_strategy,
    )
