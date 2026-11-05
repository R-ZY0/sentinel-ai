"""Week 3/4 API and worker checks; all network/broker calls are controlled."""
import json
import os
import unittest
from unittest.mock import patch, MagicMock
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker

from ..database import engine, get_db
from ..dependencies import get_current_user
from ..main import app
from ..models import User, Target, Scan, ScanConfiguration, AuditLog, AttackAttempt, ResponseEvaluation
from ..services.target_adapters import TargetAdapter, TargetAdapterError, TargetReply
from ..services.scan_control import cancellation_checkpoint, ScanCancelled
from ..tasks.scans import run_scan


class TargetAndScanTests(unittest.TestCase):
    def setUp(self):
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.sessions = sessionmaker(bind=self.connection, join_transaction_mode="create_savepoint")
        with self.sessions() as db:
            self.owner = User(id=uuid4(), email=f"{uuid4()}@example.test", password_hash="test")
            self.other = User(id=uuid4(), email=f"{uuid4()}@example.test", password_hash="test")
            db.add_all([self.owner, self.other])
            db.flush()
            db.expunge_all()
            db.commit()
        self.current_user = self.owner

        def database():
            with self.sessions() as db:
                yield db

        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_current_user] = lambda: self.current_user
        self.client = TestClient(app, raise_server_exceptions=False)
        self.payload = {"name": "Owned Ollama", "endpoint": "http://ollama:11434/", "authorized": True}

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.transaction.rollback()
        self.connection.close()

    def target(self, **changes):
        reply = self.client.post("/targets", json={**self.payload, **changes})
        self.assertEqual(reply.status_code, 201, reply.text)
        return reply.json()

    def scan(self, **changes):
        target_id = changes.pop("target_id", None) or self.target()["id"]
        reply = self.client.post("/scans", json={"target_id": target_id, **changes})
        self.assertEqual(reply.status_code, 201, reply.text)
        return reply.json()

    def test_new_targets_and_scans_are_private(self):
        target = self.target()
        scan = self.scan(target_id=target["id"])
        self.assertEqual(target["owner_id"], str(self.owner.id))
        self.current_user = self.other
        for path in [f"/targets/{target['id']}", f"/scans/{scan['id']}"]:
            self.assertEqual(self.client.get(path).status_code, 404)
        for suffix in ("start", "cancel"):
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/{suffix}").status_code, 404)
        self.assertEqual(self.client.post(f"/targets/{target['id']}/validate").status_code, 404)
        self.assertEqual(self.client.put(f"/targets/{target['id']}", json=self.payload).status_code, 404)
        self.assertEqual(self.client.delete(f"/targets/{target['id']}").status_code, 404)
        self.assertNotIn(target["id"], [t["id"] for t in self.client.get("/targets").json()])
        self.assertNotIn(scan["id"], [s["id"] for s in self.client.get("/scans").json()])

    def test_legacy_unowned_target_is_preserved(self):
        with self.sessions() as db:
            target = Target(name="Legacy shared target", endpoint=self.payload["endpoint"])
            db.add(target)
            db.flush()
            id = target.id
            db.commit()
        self.assertIsNone(self.client.get(f"/targets/{id}").json()["owner_id"])

    def test_validation_persists_result_and_audit_without_response(self):
        target = self.target()
        with patch("app.routers.targets.get_target_adapter") as adapter:
            adapter.return_value.respond.return_value = TargetReply("private model response", "completed", 12)
            reply = self.client.post(f"/targets/{target['id']}/validate")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json()["status"], "valid")
        self.assertNotIn("private model response", reply.text)
        self.assertEqual(self.client.get(f"/targets/{target['id']}").json()["validation_status"], "valid")
        with self.sessions() as db:
            entry = db.scalar(select(AuditLog).where(AuditLog.resource_id == target["id"], AuditLog.action == "target.validated"))
            self.assertEqual(entry.actor_id, self.owner.id)

    def test_unauthorized_and_unapproved_targets_never_make_network_calls(self):
        for values in ({"authorized": False}, {"endpoint": "http://unapproved.example.test/"}):
            target = self.target(**values)
            with patch("app.services.target_adapters.build_opener") as network:
                reply = self.client.post(f"/targets/{target['id']}/validate")
                self.assertEqual(reply.json()["status"], "invalid")
                network.assert_not_called()

    def test_rest_configuration_is_prepared_but_not_scanned_with_local_fixture(self):
        target = self.target(target_type="rest", endpoint="https://target.example.test/chat",
            configuration={"prompt_field": "input", "response_field": "output.text", "static_body": {"model": "demo"}})
        response = self.client.post("/scans", json={"target_id": target["id"]})
        self.assertEqual(response.status_code, 422)

    def test_invalid_target_configuration_is_rejected(self):
        for changes in [{"endpoint": "http://user:password@localhost/"},
                        {"endpoint": "http://localhost/?token=secret"},
                        {"target_type": "unknown"}, {"configuration": {"timeout_seconds": 0}},
                        {"configuration": {"unknown": True}},
                        {"target_type": "rest", "configuration": {"static_body": {"prompt": "override"}}}]:
            with self.subTest(changes=changes):
                self.assertEqual(self.client.post("/targets", json={**self.payload, **changes}).status_code, 422)

    def test_create_snapshots_selected_attacks_without_queueing(self):
        with patch("app.routers.scans.run_scan.apply_async") as queue:
            scan = self.scan(configuration={"engines": ["library"], "attack_ids": ["SPL-001"]})
            queue.assert_not_called()
        self.assertEqual(scan["status"], "created")
        self.assertEqual(scan["configuration"]["attack_ids"], ["SPL-001"])
        with self.sessions() as db:
            configuration = db.scalar(select(ScanConfiguration).where(ScanConfiguration.scan_id == UUID(scan["id"])))
            self.assertTrue(configuration.target_snapshot["authorized"])
            self.assertEqual(configuration.selections[0].definition["id"], "SPL-001")

    def test_start_queues_once_and_cannot_update_active_target(self):
        scan = self.scan()
        with patch("app.routers.scans.run_scan.apply_async") as queue:
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/start").status_code, 202)
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/start").status_code, 409)
            queue.assert_called_once()
        self.assertEqual(self.client.put(f"/targets/{scan['target_id']}", json=self.payload).status_code, 409)

    def test_changed_configuration_cannot_start_old_scan(self):
        scan = self.scan()
        self.client.put(f"/targets/{scan['target_id']}", json={**self.payload, "authorized": False})
        with patch("app.routers.scans.run_scan.apply_async") as queue:
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/start").status_code, 409)
            queue.assert_not_called()

    def test_invalid_attack_selection_and_pagination(self):
        target = self.target()
        for config in [{"engines": ["library"], "attack_ids": ["missing"]},
                       {"engines": ["pyrit"], "attack_ids": ["SPL-001"]},
                       {"engines": ["pyrit", "pyrit"]}]:
            self.assertEqual(self.client.post("/scans", json={"target_id": target["id"], "configuration": config}).status_code, 422)
        for path in ("/scans?status=invalid", "/scans?limit=0", "/targets?offset=-1"):
            self.assertEqual(self.client.get(path).status_code, 422)

    def test_list_filters_and_attack_catalog(self):
        scan = self.scan()
        self.assertIn(scan["id"], [s["id"] for s in self.client.get("/scans?status=created").json()])
        self.assertNotIn(scan["id"], [s["id"] for s in self.client.get("/scans?status=completed").json()])
        reply = self.client.get("/attacks")
        self.assertEqual(reply.status_code, 200)
        self.assertIn("SPL-001", [item["id"] for item in reply.json()])

    def test_cancel_created_is_idempotent_and_never_claimed(self):
        scan = self.scan()
        for _ in range(2):
            self.assertEqual(self.client.post(f"/scans/{scan['id']}/cancel").json()["status"], "cancelled")
        with patch("app.tasks.scans.SessionLocal", self.sessions), patch("app.services.week2_runner.Week2AttackRunner.run") as runner:
            self.assertTrue(run_scan.run(scan["id"])["skipped"])
            runner.assert_not_called()
        with self.assertRaises(ScanCancelled):
            cancellation_checkpoint(self.sessions, UUID(scan["id"]))

    def test_cancellation_wins_over_late_worker_completion(self):
        scan = self.scan()
        with patch("app.routers.scans.run_scan.apply_async"):
            self.client.post(f"/scans/{scan['id']}/start")

        def finish_after_cancel(*args):
            with self.sessions() as db:
                db.execute(update(Scan).where(Scan.id == UUID(scan["id"])).values(status="cancelled"))
                db.commit()
            return {"scan_id": scan["id"]}

        with patch("app.tasks.scans.SessionLocal", self.sessions), patch("app.services.week2_runner.Week2AttackRunner.run", side_effect=finish_after_cancel):
            run_scan.run(scan["id"])
        self.assertEqual(self.client.get(f"/scans/{scan['id']}").json()["status"], "cancelled")

    def test_worker_failure_is_recorded_and_finished_scan_cannot_cancel(self):
        scan = self.scan()
        with patch("app.routers.scans.run_scan.apply_async"):
            self.client.post(f"/scans/{scan['id']}/start")
        with patch("app.tasks.scans.SessionLocal", self.sessions), patch("app.services.week2_runner.Week2AttackRunner.run", side_effect=RuntimeError("private error")):
            with self.assertLogs("app.tasks.scans", level="ERROR"), self.assertRaises(RuntimeError):
                run_scan.run(scan["id"])
        result = self.client.get(f"/scans/{scan['id']}").json()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "execution_failed")
        self.assertIsNotNone(result["finished_at"])
        self.assertNotIn("private error", str(result))
        self.assertEqual(self.client.post(f"/scans/{scan['id']}/cancel").status_code, 409)

    def test_selected_library_definition_is_executed_and_linked(self):
        scan = self.scan(configuration={"engines": ["library"], "attack_ids": ["SPL-002"]})
        with patch("app.routers.scans.run_scan.apply_async"):
            self.client.post(f"/scans/{scan['id']}/start")
        fixture = {"test_case_id": "TC-002", "target_authorized": True,
                   "requester_authorized": False, "source_verified": True,
                   "fixture_loaded": True,
                   "values": [{"id": "fixture", "kind": "canary", "value": "SYNTHETIC_TEST_REFERENCE"}]}

        def review(attack, **kwargs):
            return {"attack_id": attack.attack_id, "advisory_only": True,
                    "baselines": {name: {"verdict": "NO_LEAK", "confidence": 1.0,
                    "reason": "Controlled", "signals": {}} for name in ("B0", "B1", "B2", "B3")}}

        with patch("app.tasks.scans.SessionLocal", self.sessions), \
             patch("app.services.week2_runner.SessionLocal", self.sessions), \
             patch("app.services.week2_runner.execute_canary_probe", return_value=("I cannot disclose it.", "SYNTHETIC_TEST_REFERENCE", fixture)) as target, \
             patch("app.services.week2_runner.review_attack", side_effect=review):
            result = run_scan.run(scan["id"])
        self.assertEqual(result["results"][0]["attack_case_id"], "SPL-002")
        with self.sessions() as db:
            configuration = db.scalar(select(ScanConfiguration).where(ScanConfiguration.scan_id == UUID(scan["id"])))
            self.assertEqual(target.call_args.args[0], configuration.selections[0].definition["payload"])
            attempt = db.scalar(select(AttackAttempt).where(AttackAttempt.scan_id == UUID(scan["id"])))
            self.assertEqual(attempt.attack_id, "SPL-002")
            self.assertEqual(db.get(Scan, UUID(scan["id"])).status, "completed")

    def test_cancellation_during_judging_discards_new_evaluation(self):
        scan = self.scan()
        from attack_engine.attack_run import AttackRun
        from ..services.week2_runner import Week2AttackRunner
        attack = AttackRun(attack_id="SPL-001", category="test", payload="test",
            target="http://ollama:11434", strategy="test", expected_behavior="protect",
            status="completed", actual_response="controlled response")

        def cancel(*args, **kwargs):
            self.client.post(f"/scans/{scan['id']}/cancel")
            return {"attack_id": "SPL-001", "baselines": {}}

        with patch("app.services.week2_runner.SessionLocal", self.sessions), \
             patch("app.services.week2_runner.review_attack", side_effect=cancel), \
             self.assertRaises(ScanCancelled):
            Week2AttackRunner()._evaluate(UUID(scan["id"]), attack, "fixture", {}, "library")
        with self.sessions() as db:
            attempt = db.scalar(select(AttackAttempt).where(AttackAttempt.scan_id == UUID(scan["id"])))
            self.assertIsNotNone(attempt)
            response = attempt.responses[0]
            self.assertIsNone(db.scalar(select(ResponseEvaluation).where(ResponseEvaluation.response_id == response.id)))


class TargetAdapterTests(unittest.TestCase):
    def test_rest_adapter_maps_request_and_nested_reply(self):
        target = Target(target_type="rest", endpoint="https://target.example.test/chat", authorized=True,
            configuration={"prompt_field": "input", "response_field": "output.text", "static_body": {"model": "demo"}})
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"output":{"text":"OK"}}'
        with patch.dict(os.environ, {"TARGET_ALLOWED_ENDPOINTS": target.endpoint}), patch("app.services.target_adapters.build_opener") as network:
            network.return_value.open.return_value = response
            self.assertEqual(TargetAdapter(target).respond("hello").response, "OK")
            request = network.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(request.data), {"input": "hello", "model": "demo"})

    def test_invalid_and_oversized_replies_are_rejected(self):
        target = Target(target_type="ollama", endpoint="http://ollama:11434/", authorized=True, configuration={})
        for raw in (b'{}', b'not JSON', b'x' * (1024 * 1024 + 1)):
            response = MagicMock()
            response.__enter__.return_value.read.return_value = raw
            with patch("app.services.target_adapters.build_opener") as network:
                network.return_value.open.return_value = response
                with self.assertRaises(TargetAdapterError):
                    TargetAdapter(target).respond("hello")
