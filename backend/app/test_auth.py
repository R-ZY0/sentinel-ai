import unittest
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from .database import engine, get_db
from .main import app
from .models import User
from .passwords import verify_password
from .tokens import ALGORITHM, get_signing_key


class AuthTests(unittest.TestCase):
    
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
        self.client = TestClient(app, raise_server_exceptions=False)
        self.email = f"auth-{uuid4().hex}@example.com"
        self.password = "TemporaryTestPassword2026!"

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        try:
            self.transaction.rollback()
        finally:
            self.connection.close()

    def register_user(self):
        response = self.client.post(
            "/auth/register",
            json={"email": self.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 201)
        return response.json()

    def test_registration_login_and_me(self):
        account = self.register_user()
        self.assertNotIn("password", account)
        self.assertNotIn("password_hash", account)

        with self.sessions() as db:
            user = db.get(User, UUID(account["id"]))
            self.assertNotEqual(user.password_hash, self.password)
            self.assertTrue(
                verify_password(self.password, user.password_hash)
            )

        login = self.client.post(
            "/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json()["token_type"], "bearer")

        response = self.client.get(
            "/auth/me",
            headers={
                "Authorization": f"Bearer {login.json()['access_token']}"
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), account)

    def test_duplicate_email_is_case_insensitive(self):
        self.register_user()
        response = self.client.post(
            "/auth/register",
            json={
                "email": self.email.upper(),
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, 409)

    def test_invalid_registration_is_rejected(self):
        for payload in [
            {"email": self.email, "password": "short"},
            {"email": "not-an-email", "password": self.password},
            {"email": self.email},
        ]:
            with self.subTest(payload=payload):
                response = self.client.post("/auth/register", json=payload)
                self.assertEqual(response.status_code, 422)

    def test_wrong_password_and_unknown_user_return_same_error(self):
        self.register_user()
        for email, password in [
            (self.email, "WrongPassword2026!"),
            (f"missing-{uuid4().hex}@example.com", self.password),
        ]:
            response = self.client.post(
                "/auth/login",
                data={"username": email, "password": password},
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(
                response.json(),
                {"detail": "Incorrect email or password"},
            )

    def test_missing_invalid_and_expired_tokens_are_rejected(self):
        self.assertEqual(self.client.get("/auth/me").status_code, 401)
        account = self.register_user()
        now = datetime.now(timezone.utc)
        expired_token = jwt.encode(
            {
                "sub": account["id"],
                "iat": now - timedelta(hours=1),
                "exp": now - timedelta(minutes=1),
            },
            get_signing_key(),
            algorithm=ALGORITHM,
        )

        for token in ["invalid-token", expired_token]:
            response = self.client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(
                response.json(),
                {"detail": "Could not validate credentials"},
            )

    def test_inactive_user_cannot_login_or_use_existing_token(self):
        account = self.register_user()
        login = self.client.post(
            "/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]

        with self.sessions() as db:
            user = db.get(User, UUID(account["id"]))
            user.is_active = False
            db.commit()

        login = self.client.post(
            "/auth/login",
            data={"username": self.email, "password": self.password},
        )
        self.assertEqual(login.status_code, 401)

        response = self.client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 401)

    def test_target_and_scan_routes_require_login(self):
        record_id = str(uuid4())
        requests = [
            ("GET", "/targets", None),
            ("POST", "/targets", {
                "name": "Unauthorized target",
                "endpoint": "http://ollama:11434/",
            }),
            ("GET", f"/targets/{record_id}", None),
            ("PUT", f"/targets/{record_id}", {
                "name": "Unauthorized update",
                "endpoint": "http://ollama:11434/",
            }),
            ("DELETE", f"/targets/{record_id}", None),
            ("POST", "/scans", {"target_id": record_id}),
            ("GET", f"/scans/{record_id}", None),
        ]

        for method, path, payload in requests:
            with self.subTest(method=method, path=path):
                response = self.client.request(
                    method, path, json=payload
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.json(),
                    {"detail": "Not authenticated"},
                )
if __name__ == "__main__":
    unittest.main()