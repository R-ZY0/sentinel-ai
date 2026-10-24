"""No-network checks for 1-case default vs opted-in full 15-case scan."""
import os
import unittest
from unittest.mock import patch

from attack_engine.attack_library import ATTACK_LIBRARY
from app.attack_engine import AttackEngine


class FullScanSelectionTests(unittest.TestCase):
    def test_default_keeps_p0_one_case(self):
        with patch.dict(os.environ, {}, clear=True):
            engine = AttackEngine()
        self.assertEqual(engine.profile, "week1_local")
        self.assertEqual([x.attack_case_id for x in engine.probes()], ["SPL-001"])

    def test_full_profile_selects_all_unique_library_probes(self):
        engine = AttackEngine(profile="full_local")
        probes = engine.probes()
        self.assertEqual(len(probes), 15)
        self.assertEqual(len({p.attack_case_id for p in probes}), 15)
        self.assertEqual(
            [p.attack_case_id for p in probes],
            [case.attack_id for case in ATTACK_LIBRARY],
        )
        self.assertEqual(len({p.category for p in probes}), 5)

    def test_profile_can_be_selected_by_environment(self):
        with patch.dict(os.environ, {"SENTINEL_SCAN_PROFILE": "full_local"}):
            self.assertEqual(len(AttackEngine().probes()), 15)

    def test_invalid_profile_fails_closed(self):
        for value in ("", "all", "demo_vulnerable", "FULL", "full"):
            with self.subTest(profile=value):
                with self.assertRaises(ValueError):
                    AttackEngine(profile=value)


if __name__ == "__main__":
    unittest.main()
