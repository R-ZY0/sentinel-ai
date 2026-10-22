import unittest

from backend.app.attack_engine import Probe
from backend.app.attack_library import ATTACK_LIBRARY


class AttackLibraryAdapterTests(unittest.TestCase):
    def test_each_attack_can_be_converted_to_probe(self):
        for attack in ATTACK_LIBRARY:
            with self.subTest(attack_id=attack.attack_id):
                probe = Probe(
                    category=attack.category,
                    payload=attack.payload,
                )
                self.assertEqual(probe.category, attack.category)
                self.assertEqual(probe.payload, attack.payload)


if __name__ == "__main__":
    unittest.main()
