import unittest

from .attack_engine import AttackEngine
from .attack_library import ATTACK_LIBRARY


class AttackEngineTests(unittest.TestCase):
    def test_engine_returns_all_library_attacks(self):
        probes = AttackEngine().probes()
        self.assertEqual(len(probes), len(ATTACK_LIBRARY))

    def test_engine_preserves_categories_and_payloads(self):
        probes = AttackEngine().probes()
        expected = [
            (attack.category, attack.payload)
            for attack in ATTACK_LIBRARY
        ]
        actual = [
            (probe.category, probe.payload)
            for probe in probes
        ]
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
