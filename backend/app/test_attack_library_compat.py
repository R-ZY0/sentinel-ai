import unittest
from collections import Counter
from backend.app.attack_library import ATTACK_LIBRARY

class AttackLibraryCompatibilityTests(unittest.TestCase):
    def test_library_structure(self):
        self.assertEqual(len(ATTACK_LIBRARY), 15)
        self.assertEqual(len({a.attack_id for a in ATTACK_LIBRARY}), 15)
        self.assertEqual(
            set(Counter(a.category for a in ATTACK_LIBRARY)),
            {
                "Prompt Injection",
                "System Prompt Leakage",
                "Data Leakage",
                "RAG Leakage",
                "Jailbreak",
            },
        )

    def test_required_fields(self):
        for attack in ATTACK_LIBRARY:
            for field in (
                "attack_id", "category", "payload",
                "strategy", "expected_behavior"
            ):
                self.assertTrue(
                    getattr(attack, field, None),
                    f"Missing {field} in {attack.attack_id}",
                )

if __name__ == "__main__":
    unittest.main()
