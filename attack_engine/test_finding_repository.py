import os
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from attack_engine.finding import Finding
from attack_engine.finding_repository import FindingRepository


class TestFindingRepository(unittest.TestCase):

    @patch.dict(os.environ, {"POSTGRES_PASSWORD": "test-password"})
    @patch("attack_engine.finding_repository.psycopg.connect")
    def test_save_executes_insert_and_commits(self, mock_connect):
        connection = MagicMock()
        cursor = MagicMock()

        mock_connect.return_value.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor

        finding = Finding(
            finding_id="finding-test-001",
            attack_id="attack-test-001",
            category="Prompt Injection",
            title="Test finding",
            severity="Medium",
            description="Test description",
            evidence="PWNED",
            remediation="Review prompt handling",
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
        )

        repository = FindingRepository()
        repository.save(finding)

        mock_connect.assert_called_once()
        cursor.execute.assert_called_once()
        connection.commit.assert_called_once()

        sql, values = cursor.execute.call_args.args

        self.assertIn("INSERT INTO findings", sql)
        self.assertEqual(
            values,
            (
                finding.finding_id,
                finding.attack_id,
                finding.category,
                finding.title,
                finding.severity,
                finding.description,
                finding.evidence,
                finding.remediation,
                finding.timestamp,
            ),
        )

    @patch.dict(os.environ, {}, clear=True)
    @patch("attack_engine.finding_repository.psycopg.connect")
    def test_missing_password_raises_error(self, mock_connect):
        with self.assertRaisesRegex(
            ValueError,
            "POSTGRES_PASSWORD",
        ):
            FindingRepository()

        mock_connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
