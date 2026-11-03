import unittest

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_schema import AttackDefinition
from attack_engine.normalized_attack_library import (
    NORMALIZED_ATTACK_LIBRARY,
    NORMALIZED_ATTACK_REGISTRY,
)


class TestNormalizedAttackLibrary(unittest.TestCase):
    def test_normalized_library_contains_all_legacy_attacks(self):
        self.assertEqual(len(NORMALIZED_ATTACK_LIBRARY), len(ATTACK_LIBRARY))
        self.assertEqual(len(NORMALIZED_ATTACK_LIBRARY), 15)

    def test_every_entry_is_an_attack_definition(self):
        self.assertTrue(
            all(isinstance(item, AttackDefinition)
                for item in NORMALIZED_ATTACK_LIBRARY)
        )

    def test_stable_attack_ids_are_preserved(self):
        legacy_ids = [item.attack_id for item in ATTACK_LIBRARY]
        normalized_ids = [item.attack_id for item in NORMALIZED_ATTACK_LIBRARY]
        self.assertEqual(normalized_ids, legacy_ids)

    def test_every_definition_has_required_fields(self):
        for item in NORMALIZED_ATTACK_LIBRARY:
            self.assertTrue(item.attack_id.strip())
            self.assertTrue(item.category.strip())
            self.assertTrue(item.goal.strip())
            self.assertTrue(item.strategy.strip())
            self.assertTrue(item.payload.strip())
            self.assertTrue(item.expected_behavior.strip())

    def test_every_definition_has_explicit_mutation_metadata(self):
        for item in NORMALIZED_ATTACK_LIBRARY:
            self.assertTrue(item.mutation_supported)
            self.assertIsNotNone(item.mutation_strategy)
            self.assertTrue(item.mutation_strategy.strip())

    def test_owasp_mapping_is_not_invented(self):
        self.assertTrue(
            all(item.owasp_mapping is None
                for item in NORMALIZED_ATTACK_LIBRARY)
        )

    def test_normalized_registry_contains_all_attacks(self):
        self.assertEqual(len(NORMALIZED_ATTACK_REGISTRY), 15)

    def test_all_five_categories_are_represented(self):
        expected = {
            "Prompt Injection",
            "System Prompt Leakage",
            "Data Leakage",
            "RAG Leakage",
            "Jailbreak",
        }
        self.assertEqual(
            set(NORMALIZED_ATTACK_REGISTRY.categories()),
            expected,
        )

    def test_each_category_has_three_attacks(self):
        for category in NORMALIZED_ATTACK_REGISTRY.categories():
            self.assertEqual(
                len(NORMALIZED_ATTACK_REGISTRY.by_category(category)),
                3,
            )

    def test_legacy_library_remains_unchanged(self):
        for legacy, normalized in zip(
            ATTACK_LIBRARY, NORMALIZED_ATTACK_LIBRARY
        ):
            self.assertEqual(legacy.attack_id, normalized.attack_id)
            self.assertEqual(legacy.category, normalized.category)
            self.assertEqual(legacy.payload, normalized.payload)
            self.assertEqual(legacy.strategy, normalized.strategy)
            self.assertEqual(
                legacy.expected_behavior,
                normalized.expected_behavior,
            )


if __name__ == "__main__":
    unittest.main()
