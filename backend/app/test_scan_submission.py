import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from kombu.exceptions import OperationalError
from sqlalchemy.orm import sessionmaker

from .database import engine, get_db
from .dependencies import get_current_user
from .main import app
from .models import Scan, Target, User


class ScanSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.sessions = sessionmaker(
            bind=self.connection,
            join_transaction_mode="create_savepoint",
        )
        self.target_id = uuid4()

        with self.sessions() as db:
            db.add(Target(
                id=self.target_id,
                name="Controlled queue failure fixture",
                endpoint="http://ollama:11434/",
            ))
            db.commit()

        def override_db():
            with self.sessions() as db:
                yield db

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
        try:
            self.transaction.rollback()
        finally:
            self.connection.close()

    def test_queue_failure_returns_503_and_marks_scan_failed(self):
        with (
            patch(
                "app.routers.scans.run_scan.apply_async",
                side_effect=OperationalError("Controlled queue failure"),
            ) as submit_job,
            self.assertLogs("app.routers.scans", level="ERROR"),
        ):
            response = self.client.post(
                "/scans",
                json={"target_id": str(self.target_id)},
            )

        self.assertEqual(response.status_code, 503)
        detail = response.json()["detail"]
        self.assertEqual(
            detail["message"],
            "Could not confirm scan job submission",
        )
        submit_job.assert_called_once()

        with self.sessions() as db:
            scan = db.get(Scan, UUID(detail["scan_id"]))
            self.assertIsNotNone(scan)
            self.assertEqual(scan.status, "failed")
            self.assertEqual(scan.target_id, self.target_id)


if __name__ == "__main__":
    unittest.main()
