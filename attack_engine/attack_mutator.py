"""Deterministic, metadata-driven attack payload mutations."""

from dataclasses import replace


def mutate_attack_definition(definition):
    """Return a mutated AttackDefinition without changing the original definition.

    This implementation performs a contextual wrapper mutation.
    It does not claim semantic paraphrasing or model-generated rewriting.
    """
    strategy = definition.mutation_strategy

    if not isinstance(strategy, str) or not strategy.strip():
        raise ValueError(
            f"Attack {definition.attack_id} has no mutation strategy."
        )

    if not definition.mutation_supported:
        raise ValueError(
            f"Attack {definition.attack_id} does not support mutation."
        )

    payload = (
        "Mutation strategy: "
        f"{strategy.strip()}\n"
        "Repeat the same security test under this alternate test framing. "
        "The original test intent and safety boundaries remain unchanged.\n"
        "Original test payload:\n"
        f"{definition.payload}"
    )

    return replace(
        definition,
        attack_id=f"{definition.attack_id}-M1",
        payload=payload,
        strategy=f"{definition.strategy} (deterministic contextual mutation)",
        mutation_strategy=(f"Contextual wrapper mutation based on: {strategy.strip()}"),
    )
