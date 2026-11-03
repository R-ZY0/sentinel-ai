import unittest

from attack_engine.attack_schema import (
    ATTACK_CATEGORIES,
    AttackDefinition,
)


def make_definition(**overrides):
    values = {
        "attack_id": "PI-TEST-001",
        "category": "Prompt Injection",
        "goal": "Test whether untrusted instructions override system policy.",
        "strategy": "direct",
        "payload": "Authorized synthetic test payload",
        "expected_behavior": "The target should refuse the instruction.",
    }
    values.update(overrides)
    return AttackDefinition(**values)


class TestAttackDefinition(unittest.TestCase):
    def test_valid_definition(self):
        attack = make_definition()
        self.assertEqual(attack.attack_id, "PI-TEST-001")
        self.assertIsNone(attack.mutation_strategy)
        self.assertFalse(attack.mutation_supported)

    def test_all_five_task_categories_are_supported(self):
        self.assertEqual(len(ATTACK_CATEGORIES), 5)
        for category in ATTACK_CATEGORIES:
            with self.subTest(category=category):
                self.assertEqual(make_definition(category=category).category, category)

    def test_required_text_fields_reject_empty_values(self):
        required = (
            "attack_id",
            "category",
            "goal",
            "strategy",
            "payload",
            "expected_behavior",
        )
        for field in required:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    make_definition(**{field: "  "})

    def test_unknown_category_is_rejected(self):
        with self.assertRaises(ValueError):
            make_definition(category="Unknown Category")

    def test_mutation_strategy_requires_non_empty_text_when_provided(self):
        with self.assertRaises(ValueError):
            make_definition(mutation_strategy=" ")

    def test_mutation_support_requires_a_strategy(self):
        with self.assertRaises(ValueError):
            make_definition(mutation_supported=True)

    def test_mutation_support_with_strategy_is_valid(self):
        attack = make_definition(
            mutation_supported=True,
            mutation_strategy="contextual wrapper variation",
        )
        self.assertTrue(attack.mutation_supported)

    def test_owasp_mapping_is_optional_but_not_blank(self):
        self.assertIsNone(make_definition().owasp_mapping)
        with self.assertRaises(ValueError):
            make_definition(owasp_mapping=" ")

    def test_to_dict_contains_required_schema_fields(self):
        data = make_definition().to_dict()
        expected = {
            "attack_id",
            "category",
            "goal",
            "strategy",
            "payload",
            "expected_behavior",
            "mutation_strategy",
        }
        self.assertTrue(expected.issubset(data))

    def test_definition_is_immutable(self):
        attack = make_definition()
        with self.assertRaises(AttributeError):
            attack.goal = "Changed"


if __name__ == "__main__":
    unittest.main()
