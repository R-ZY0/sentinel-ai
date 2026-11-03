"""Central registry for normalized and legacy-compatible attack definitions."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable


class AttackRegistryError(ValueError):
    """Raised when attack definitions cannot be registered safely."""


class AttackRegistry:
    """Read-only index of attack definitions keyed by stable attack_id.

    The registry accepts existing AttackCase objects as well as normalized
    AttackDefinition objects. It does not modify the supplied definitions.
    """

    REQUIRED_FIELDS = (
        "attack_id",
        "category",
        "payload",
        "strategy",
        "expected_behavior",
    )

    def __init__(self, attacks: Iterable[object]):
        self._by_id = {}
        self._by_category = defaultdict(list)

        for attack in attacks:
            self._validate(attack)
            attack_id = attack.attack_id

            if attack_id in self._by_id:
                raise AttackRegistryError(
                    f"Duplicate attack_id: {attack_id}"
                )

            self._by_id[attack_id] = attack
            self._by_category[attack.category].append(attack)

        self._by_category = {
            category: tuple(items)
            for category, items in self._by_category.items()
        }

    @classmethod
    def _validate(cls, attack: object) -> None:
        for field_name in cls.REQUIRED_FIELDS:
            value = getattr(attack, field_name, None)
            if not isinstance(value, str) or not value.strip():
                raise AttackRegistryError(
                    f"Attack definition has invalid {field_name}."
                )

    def get(self, attack_id: str):
        """Return an attack by stable ID, or None if it is unknown."""
        return self._by_id.get(attack_id)

    def require(self, attack_id: str):
        """Return an attack by ID or raise a clear lookup error."""
        attack = self.get(attack_id)
        if attack is None:
            raise KeyError(f"Unknown attack_id: {attack_id}")
        return attack

    def by_category(self, category: str) -> tuple:
        """Return all attacks in a category in registration order."""
        return self._by_category.get(category, ())

    def all(self) -> tuple:
        """Return all registered attacks in registration order."""
        return tuple(self._by_id.values())

    def categories(self) -> tuple:
        """Return categories in first-seen order."""
        return tuple(self._by_category.keys())

    def __len__(self) -> int:
        return len(self._by_id)


def build_default_registry() -> AttackRegistry:
    """Build a registry from the existing shared attack library."""
    from attack_engine.attack_library import ATTACK_LIBRARY

    return AttackRegistry(ATTACK_LIBRARY)


ATTACK_REGISTRY = build_default_registry()
