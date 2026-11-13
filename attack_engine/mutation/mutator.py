"""Bounded, reproducible variant generation with payload deduplication."""

import hashlib
import random
import re

from attack_engine.attack_schema import AttackDefinition

from .schema import AttackVariant, MutationError
from .strategies import STRATEGIES


def _canonical(payload: str) -> str:
    return re.sub(r"\s+", " ", payload).strip().casefold()


def _fingerprint(payload: str) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


class VariantGenerator:
    """Generate at most one variant per available strategy per request.

    The caller supplies previous payloads, including prior attempts across
    processes. No implicit global state, network access, or persistence.
    """

    def generate(
        self,
        definition: AttackDefinition,
        *,
        seed: int = 0,
        count: int = 1,
        used_payloads: tuple[str, ...] | list[str] = (),
        strategies: tuple[str, ...] | list[str] | None = None,
    ) -> list[AttackVariant]:
        if not definition.mutation_supported:
            raise MutationError("Attack definition does not support mutation")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise TypeError("seed must be an integer")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("count must be a positive integer")

        available = list(strategies) if strategies is not None else list(STRATEGIES)
        if len(available) != len(set(available)) or any(s not in STRATEGIES for s in available):
            raise ValueError("Unknown or repeated mutation strategy")
        if count > len(available):
            raise MutationError("Requested more variants than available strategies")

        random.Random(seed).shuffle(available)
        seen = {_fingerprint(definition.payload)}
        seen.update(_fingerprint(value) for value in used_payloads)
        variants = []
        for position, strategy in enumerate(available, start=1):
            payload = STRATEGIES[strategy](definition.payload)
            digest = _fingerprint(payload)
            if digest in seen:
                continue
            seen.add(digest)
            variants.append(
                AttackVariant(
                    attack_id=f"{definition.attack_id}-V{seed}-{position}",
                    parent_attack_id=definition.attack_id,
                    category=definition.category,
                    goal=definition.goal,
                    strategy=definition.strategy,
                    payload=payload,
                    expected_behavior=definition.expected_behavior,
                    mutation_strategy=strategy,
                    seed=seed,
                    variant_index=position,
                    payload_sha256=digest,
                )
            )
            if len(variants) == count:
                return variants
        raise MutationError("Not enough unique variants remain for this attack")
