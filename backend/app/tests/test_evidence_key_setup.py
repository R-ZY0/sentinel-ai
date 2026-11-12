import tempfile
import unittest
from pathlib import Path
from ..tools.configure_evidence_key import configure


class EvidenceKeySetupTests(unittest.TestCase):
    def test_create_once_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("POSTGRES_PASSWORD=unchanged-test-setting\n")
            self.assertTrue(configure(path))
            content = path.read_bytes()
            self.assertIn(b"POSTGRES_PASSWORD=unchanged-test-setting", content)
            self.assertFalse(configure(path))
            self.assertEqual(path.read_bytes(), content)

    def test_invalid_existing_key_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("EVIDENCE_AUDIT_KEY=invalid\n")
            with self.assertRaises(ValueError):
                configure(path)
            self.assertEqual(path.read_text(), "EVIDENCE_AUDIT_KEY=invalid\n")

    def test_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("EVIDENCE_AUDIT_KEY=\nEVIDENCE_AUDIT_KEY=\n")
            with self.assertRaises(ValueError):
                configure(path)
