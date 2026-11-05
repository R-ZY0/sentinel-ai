"""Additive migration and database integrity checks on isolated SQLite files."""
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, inspect, text, event
from sqlalchemy.exc import IntegrityError
from ..migrations import upgrade, REVISION


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = create_engine("sqlite:///" + str(Path(self.directory.name) / "migration.db"))

        @event.listens_for(self.engine, "connect")
        def foreign_keys(connection, record):
            connection.execute("PRAGMA foreign_keys=ON")

    def tearDown(self):
        self.engine.dispose()
        self.directory.cleanup()

    def test_fresh_schema_has_required_tables_foreign_keys_and_indexes(self):
        upgrade(self.engine)
        inspector = inspect(self.engine)
        required = {"users", "targets", "scans", "scan_configurations", "attacks",
                    "attack_attempts", "responses", "findings", "evidence",
                    "vulnerability_mappings", "audit_logs", "scan_attacks"}
        self.assertTrue(required.issubset(inspector.get_table_names()))
        for table in required - {"users", "attacks"}:
            with self.subTest(table=table):
                self.assertTrue(inspector.get_foreign_keys(table))
        self.assertIn("ix_scans_status", {i["name"] for i in inspector.get_indexes("scans")})
        with self.assertRaises(IntegrityError), self.engine.begin() as connection:
            connection.execute(text("INSERT INTO scans(id,target_id,status,created_at) VALUES (:id,:target,'created',CURRENT_TIMESTAMP)"),
                               {"id": uuid4().hex, "target": uuid4().hex})

    def test_upgrade_preserves_legacy_rows_and_can_be_repeated(self):
        target_id, scan_id, attempt_id = [uuid4().hex for _ in range(3)]
        with self.engine.begin() as connection:
            connection.execute(text("CREATE TABLE users (id CHAR(32) PRIMARY KEY, email VARCHAR(320), password_hash TEXT, is_active BOOLEAN, created_at DATETIME)"))
            connection.execute(text("CREATE TABLE targets (id CHAR(32) PRIMARY KEY, name VARCHAR(100), endpoint TEXT, created_at DATETIME)"))
            connection.execute(text("CREATE TABLE scans (id CHAR(32) PRIMARY KEY, target_id CHAR(32) REFERENCES targets(id), status VARCHAR(30), created_at DATETIME)"))
            connection.execute(text("CREATE TABLE attack_attempts (id CHAR(32) PRIMARY KEY, scan_id CHAR(32) REFERENCES scans(id), category VARCHAR(100), payload TEXT, status VARCHAR(30), created_at DATETIME)"))
            connection.execute(text("INSERT INTO targets VALUES (:id,'Historical','http://ollama:11434/',CURRENT_TIMESTAMP)"), {"id": target_id})
            connection.execute(text("INSERT INTO scans VALUES (:id,:target,'completed',CURRENT_TIMESTAMP)"), {"id": scan_id, "target": target_id})
            connection.execute(text("INSERT INTO attack_attempts VALUES (:id,:scan,'test','original prompt','completed',CURRENT_TIMESTAMP)"), {"id": attempt_id, "scan": scan_id})
        upgrade(self.engine)
        upgrade(self.engine)
        with self.engine.connect() as connection:
            target = connection.execute(text("SELECT * FROM targets WHERE id=:id"), {"id": target_id}).mappings().one()
            self.assertEqual(target["target_type"], "ollama")
            self.assertIsNone(target["owner_id"])
            self.assertEqual(target["configuration"], "{}")
            self.assertEqual(connection.scalar(text("SELECT status FROM scans WHERE id=:id"), {"id": scan_id}), "completed")
            self.assertEqual(connection.scalar(text("SELECT payload FROM attack_attempts WHERE id=:id"), {"id": attempt_id}), "original prompt")
            self.assertEqual(connection.scalar(text("SELECT COUNT(*) FROM schema_revisions WHERE revision=:revision"), {"revision": REVISION}), 1)
