import unittest
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from .database import engine, get_db
from .dependencies import get_current_user
from .main import app
from .models import Scan, Target, User


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.sessions = sessionmaker(
            bind=self.connection,
            join_transaction_mode="create_savepoint",
        )

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

    def create_target(self):
        response = self.client.post(
            "/targets",
            json={
                "name": "CRUD test target",
                "endpoint": "http://ollama:11434/",
            },
        )
        self.assertEqual(response.status_code, 201)
        return response.json()

    def test_target_lifecycle(self):
        original = self.create_target()
        path = f"/targets/{original['id']}"

        fetched = self.client.get(path)
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json(), original)

        listed = self.client.get("/targets")
        self.assertEqual(listed.status_code, 200)
        self.assertIn(original, listed.json())

        updated = self.client.put(
            path,
            json={
                "name": "Updated test target",
                "endpoint": "http://ollama:11434/api/",
            },
        )
        self.assertEqual(updated.status_code, 200)
        expected = {
            **original,
            "name": "Updated test target",
            "endpoint": "http://ollama:11434/api/",
        }
        self.assertEqual(updated.json(), expected)
        self.assertEqual(self.client.get(path).json(), expected)

        deleted = self.client.delete(path)
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(deleted.content, b"")
        self.assertEqual(self.client.get(path).status_code, 404)

    def test_missing_target_returns_404(self):
        path = f"/targets/{uuid4()}"
        responses = [
            self.client.get(path),
            self.client.put(
                path,
                json={
                    "name": "Missing target",
                    "endpoint": "http://ollama:11434/",
                },
            ),
            self.client.delete(path),
        ]
        for response in responses:
            self.assertEqual(response.status_code, 404)
            self.assertEqual(
                response.json(),
                {"detail": "Target not found"},
            )

    def test_invalid_update_preserves_target(self):
        original = self.create_target()
        path = f"/targets/{original['id']}"

        for payload in [
            {},
            {"name": "Changed", "endpoint": "not-a-url"},
            {"name": "   ", "endpoint": "http://ollama:11434/"},
        ]:
            with self.subTest(payload=payload):
                response = self.client.put(path, json=payload)
                self.assertEqual(response.status_code, 422)
                self.assertEqual(self.client.get(path).json(), original)

    def test_delete_preserves_target_with_scan_history(self):
        original = self.create_target()
        target_id = UUID(original["id"])
        scan_id = uuid4()

        with self.sessions() as db:
            db.add(Scan(
                id=scan_id,
                target_id=target_id,
                status="completed",
            ))
            db.commit()

        response = self.client.delete(f"/targets/{target_id}")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {"detail": "Cannot delete a target with scan history"},
        )

        with self.sessions() as db:
            self.assertIsNotNone(db.get(Target, target_id))
            self.assertIsNotNone(db.get(Scan, scan_id))


if __name__ == "__main__":
    unittest.main()
