"""Validated, normalized attack definition schema for Sentinel AI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional


ATTACK_CATEGORIES = frozenset({
    "Prompt Injection",
    "System Prompt Leakage",
    "Data Leakage",
    "RAG Leakage",
    "Jailbreak",
})


@dataclass(frozen=True)
class AttackDefinition:
    """Canonical schema for a reusable attack-library definition.

    attack_id identifies the reusable attack definition, not an execution
    attempt. Execution/attempt identifiers belong to execution records.
    """

    attack_id: str
    category: str
    goal: str
    strategy: str
    payload: str
    expected_behavior: str
    mutation_strategy: Optional[str] = None
    mutation_supported: bool = False
    owasp_mapping: Optional[str] = None

    def __post_init__(self) -> None:
        required_text = {
            "attack_id": self.attack_id,
            "category": self.category,
            "goal": self.goal,
            "strategy": self.strategy,
            "payload": self.payload,
            "expected_behavior": self.expected_behavior,
        }

        for field_name, value in required_text.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string.")

        if self.category not in ATTACK_CATEGORIES:
            raise ValueError(
                f"Unsupported attack category: {self.category!r}"
            )

        if not isinstance(self.mutation_supported, bool):
            raise TypeError("mutation_supported must be a boolean.")

        if self.mutation_strategy is not None:
            if (
                not isinstance(self.mutation_strategy, str)
                or not self.mutation_strategy.strip()
            ):
                raise ValueError(
                    "mutation_strategy must be a non-empty string or None."
                )

        if self.mutation_supported and self.mutation_strategy is None:
            raise ValueError(
                "A mutation strategy is required when mutation is supported."
            )

        if self.owasp_mapping is not None:
            if (
                not isinstance(self.owasp_mapping, str)
                or not self.owasp_mapping.strip()
            ):
                raise ValueError(
                    "owasp_mapping must be a non-empty string or None."
                )

    def to_dict(self) -> dict:
        """Return a plain dictionary suitable for serialization."""
        return asdict(self)
