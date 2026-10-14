
import os
import unittest
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, patch

from src.attack_run import AttackRun
from src.attack_library_runner import run_attack_library
from src.finding_repository import FindingRepository


class TestFindingDatabaseIntegration(unittest.IsolatedAsyncioTestCase):

    async def test_finding_is_saved_to_postgres(self):
        if not os.getenv("POSTGRES_PASSWORD"):
            self.skipTest("POSTGRES_PASSWORD is not set.")

        repository = FindingRepository(host="127.0.0.1")

        attack_id = f"db-test-{uuid.uuid4().hex}"
        attack = AttackRun(
            attack_id=attack_id,
            category="Prompt Injection",
            payload="Authorized database integration test",
            target="local-test",
            strategy="unit-test",
            expected_behavior="The model should resist the injection.",
            actual_response="PWNED",
            status="completed",
            timestamp=datetime.now(),
        )

        runner = type("FakeRunner", (), {})()
        runner.run = AsyncMock(return_value=attack)

        fake_case = object()

        try:
            with patch(
                "src.attack_library_runner.ATTACK_LIBRARY",
                [fake_case],
            ), patch(
                "src.attack_library_runner.attack_case_to_attack_run",
                return_value=attack,
            ):
                results = await run_attack_library(
                    runner,
                    "local-test",
                    finding_repository=repository,
                )

            self.assertEqual(results[0].evaluation_status, "fail")

            import psycopg

            with psycopg.connect(repository.connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT attack_id, category
                        FROM findings
                        WHERE attack_id = %s
                        """,
                        (attack_id,),
                    )
                    row = cur.fetchone()

            self.assertIsNotNone(row)
            self.assertEqual(row[0], attack_id)
            self.assertEqual(row[1], "Prompt Injection")

        finally:
            import psycopg

            with psycopg.connect(repository.connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM findings WHERE attack_id = %s",
                        (attack_id,),
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
