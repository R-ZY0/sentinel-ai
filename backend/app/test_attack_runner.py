import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from backend.app.attack_runner import AttackRunner


class AttackRunnerTests(unittest.TestCase):
    def test_rejects_missing_target(self):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = None

        with patch("backend.app.attack_runner.SessionLocal", return_value=session):
            with self.assertRaisesRegex(ValueError, "Target not found"):
                AttackRunner().run(uuid4(), uuid4())


if __name__ == "__main__":
    unittest.main()
