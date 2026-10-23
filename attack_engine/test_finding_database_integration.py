
import unittest
import uuid
from unittest.mock import AsyncMock, patch

from sqlalchemy import select

from app.database import SessionLocal
from app.models import AttackAttempt, Finding, Response, Scan, Target
from attack_engine.attack_run import AttackRun
from attack_engine.attack_library_runner import run_attack_library


class TestFindingDatabaseIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_finding_is_saved_to_postgres(self):
        suffix = uuid.uuid4().hex[:8]
        attack_id = f"db-{suffix}"
        target_id = uuid.uuid4()
        scan_id = uuid.uuid4()

        attack = AttackRun(
            attack_id=attack_id,
            category="Prompt Injection",
            payload="Authorized database integration test",
            target="local-test",
            strategy="unit-test",
            expected_behavior="The model should resist the injection.",
            actual_response="PWNED",
            status="completed",
        )

        runner = type("FakeRunner", (), {})()
        runner.run = AsyncMock(return_value=attack)

        with (
            patch(
                "attack_engine.attack_library_runner.ATTACK_LIBRARY",
                [object()],
            ),
            patch(
                "attack_engine.attack_library_runner.attack_case_to_attack_run",
                return_value=attack,
            ),
        ):
            results = await run_attack_library(
                runner,
                "local-test",
                finding_repository=None,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, "fail")

        with SessionLocal() as db:
            try:
                target = Target(
                    id=target_id,
                    name="Finding integration test",
                    endpoint="http://ollama:11434/",
                )
                db.add(target)
                db.flush()

                scan = Scan(
                    id=scan_id,
                    target_id=target_id,
                    status="queued",
                )
                db.add(scan)
                db.flush()

                attempt = AttackAttempt(
                    scan_id=scan_id,
                    attack_id=attack_id,
                    category="Prompt Injection",
                    payload=attack.payload,
                    status="completed",
                )
                db.add(attempt)
                db.flush()

                response = Response(
                    attack_attempt_id=attempt.id,
                    content=attack.actual_response,
                )
                db.add(response)
                db.flush()

                finding = Finding(
                    response_id=response.id,
                    category="Prompt Injection",
                    severity="unassessed",
                    status="suspected",
                    evidence=attack.actual_response,
                )
                db.add(finding)
                db.commit()

                finding_id = finding.id

                saved = db.scalar(
                    select(Finding).where(Finding.id == finding_id)
                )
                self.assertIsNotNone(saved)
                self.assertEqual(saved.evidence, "PWNED")
                self.assertEqual(saved.status, "suspected")

            finally:
                db.rollback()
                if db.get(Finding, finding_id) if "finding_id" in locals() else False:
                    db.delete(db.get(Finding, finding_id))
                if db.get(Response, response.id) if "response" in locals() else False:
                    db.delete(db.get(Response, response.id))
                if db.get(AttackAttempt, attempt.id) if "attempt" in locals() else False:
                    db.delete(db.get(AttackAttempt, attempt.id))
                if db.get(Scan, scan_id):
                    db.delete(db.get(Scan, scan_id))
                if db.get(Target, target_id):
                    db.delete(db.get(Target, target_id))
                db.commit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
