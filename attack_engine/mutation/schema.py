"""Local variant contract; does not modify the shared AttackRun contract."""

from dataclasses import dataclass


class MutationError(ValueError):
    """No valid, distinct variant can be produced for the requested attack."""


@dataclass(frozen=True)
class AttackVariant:
    attack_id: str
    parent_attack_id: str
    category: str
    goal: str
    strategy: str
    payload: str
    expected_behavior: str
    mutation_strategy: str
    seed: int
    variant_index: int
    payload_sha256: str

    def __post_init__(self):
        if self.attack_id == self.parent_attack_id:
            raise ValueError("A variant must have a distinct attack ID")
        if not self.payload.strip() or not self.parent_attack_id.strip():
            raise ValueError("Payload and parent ID are required")
        if self.variant_index < 1:
            raise ValueError("variant_index must be positive")
