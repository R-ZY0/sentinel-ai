import unittest

from attack_engine.attack_library import ATTACK_LIBRARY, AttackCase
from attack_engine.attack_registry import (
    ATTACK_REGISTRY,
    AttackRegistry,
    AttackRegistryError,
)


def make_attack(attack_id="TEST-001", category="Prompt Injection"):
    return AttackCase(
        attack_id=attack_id,
        category=category,
        payload="Synthetic authorized test payload",
        strategy="direct",
        expected_behavior="The target should resist the test.",
    )


class TestAttackRegistry(unittest.TestCase):
    def test_default_registry_contains_existing_library(self):
        self.assertEqual(len(ATTACK_REGISTRY), len(ATTACK_LIBRARY))
        self.assertEqual(len(ATTACK_REGISTRY), 15)

    def test_all_existing_attack_ids_are_unique(self):
        ids = [attack.attack_id for attack in ATTACK_REGISTRY.all()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_lookup_by_id(self):
        original = ATTACK_LIBRARY[0]
        self.assertIs(ATTACK_REGISTRY.get(original.attack_id), original)

    def test_require_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            ATTACK_REGISTRY.require("UNKNOWN-ATTACK")

    def test_unknown_category_returns_empty_tuple(self):
        self.assertEqual(ATTACK_REGISTRY.by_category("Unknown"), ())

    def test_category_lookup_preserves_all_existing_cases(self):
        total = sum(
            len(ATTACK_REGISTRY.by_category(category))
            for category in ATTACK_REGISTRY.categories()
        )
        self.assertEqual(total, len(ATTACK_LIBRARY))

    def test_duplicate_attack_id_is_rejected(self):
        with self.assertRaises(AttackRegistryError):
            AttackRegistry([
                make_attack("DUP-001"),
                make_attack("DUP-001", "Jailbreak"),
            ])

    def test_missing_required_field_is_rejected(self):
        invalid = make_attack()
        invalid.payload = " "
        with self.assertRaises(AttackRegistryError):
            AttackRegistry([invalid])

    def test_registry_preserves_registration_order(self):
        attacks = [make_attack("TEST-001"), make_attack("TEST-002")]
        registry = AttackRegistry(attacks)
        self.assertEqual(
            [item.attack_id for item in registry.all()],
            ["TEST-001", "TEST-002"],
        )

    def test_registry_does_not_modify_attack_definitions(self):
        attack = make_attack()
        original_payload = attack.payload
        AttackRegistry([attack])
        self.assertEqual(attack.payload, original_payload)


if __name__ == "__main__":
    unittest.main()
