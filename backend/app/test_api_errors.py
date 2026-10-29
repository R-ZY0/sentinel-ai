import unittest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .database import get_db
from .dependencies import get_current_user
from .main import app
from .models import User


class ApiErrorTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()

        def override_db():
            yield self.db

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = lambda: User(
            email="test-user@example.com",
            password_hash="unused-in-this-test",
            is_active=True,
        )
        self.client = TestClient(app, raise_server_exceptions=False)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()

    def submit_target(self):
        return self.client.post(
            "/targets",
            json={
                "name": "Controlled error fixture",
                "endpoint": "http://ollama:11434",
            },
        )

    def test_database_conflict_returns_409(self):
        self.db.commit.side_effect = IntegrityError(
            "controlled statement",
            {},
            Exception("internal conflict details"),
        )

        with self.assertLogs("app.error_handlers", level="ERROR"):
            response = self.submit_target()

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {"detail": "The request conflicts with existing data"},
        )

    def test_database_error_returns_503(self):
        self.db.commit.side_effect = SQLAlchemyError(
            "internal database details"
        )

        with self.assertLogs("app.error_handlers", level="ERROR"):
            response = self.submit_target()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"detail": "Database operation unavailable"},
        )

    def test_unexpected_error_returns_500(self):
        self.db.commit.side_effect = RuntimeError(
            "internal application details"
        )

        with self.assertLogs("app.error_handlers", level="ERROR"):
            response = self.submit_target()

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"detail": "An unexpected error occurred"},
        )


if __name__ == "__main__":
    unittest.main()
