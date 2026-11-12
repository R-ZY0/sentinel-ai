"""Versioned, additive migrations for SQLite tests and PostgreSQL deployment.

No history/ownership is guessed, deleted or rewritten. A transaction-scoped
PostgreSQL advisory lock serializes API startup upgrades.
"""
from datetime import datetime, timezone
from sqlalchemy import inspect, text
from .database import Base

REVISION = "0003_week34_integration"


def upgrade(engine):
    from . import models  # register metadata
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            connection.execute(text("SELECT pg_advisory_xact_lock(7319402)"))
        connection.execute(text("CREATE TABLE IF NOT EXISTS schema_revisions (revision VARCHAR(80) PRIMARY KEY, applied_at VARCHAR(80) NOT NULL)"))
        # Existing tables need additive columns before create_all constructs indexes.
        additions = {
            "targets": {
                "target_type": "VARCHAR(30) NOT NULL DEFAULT 'ollama'",
                "configuration": "JSON NOT NULL DEFAULT '{}'",
                "owner_id": "UUID REFERENCES users(id)",
                "authorized": "BOOLEAN NOT NULL DEFAULT TRUE",
                "validation_status": "VARCHAR(30) NOT NULL DEFAULT 'not_validated'",
                "validated_at": "TIMESTAMP WITH TIME ZONE",
            },
            "scans": {
                "owner_id": "UUID REFERENCES users(id)",
                "started_at": "TIMESTAMP WITH TIME ZONE",
                "finished_at": "TIMESTAMP WITH TIME ZONE",
                "error_code": "VARCHAR(80)", "task_id": "VARCHAR(36)",
            },
            "attack_attempts": {
                "test_case_id": "VARCHAR(30)",
                "execution_metadata": "JSON",
                "attack_case_id": "VARCHAR(100)",
                # attacks is created below before this FK is added.
                "attack_id": "VARCHAR(100) REFERENCES attacks(id)",
            },
        }
        # Create catalog before adding the optional historical-attempt FK.
        models.Attack.__table__.create(connection, checkfirst=True)
        tables = set(inspect(connection).get_table_names())
        for table, columns in additions.items():
            if table not in tables:
                continue
            present = {c["name"] for c in inspect(connection).get_columns(table)}
            for name, ddl in columns.items():
                if name not in present:
                    if connection.dialect.name == "sqlite":
                        ddl = ddl.replace("TIMESTAMP WITH TIME ZONE", "DATETIME")
                    connection.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}'))
        Base.metadata.create_all(connection)
        for table, column in [("targets", "owner_id"), ("scans", "owner_id"),
                              ("scans", "target_id"), ("scans", "status"),
                              ("attack_attempts", "attack_id"), ("attack_attempts", "attack_case_id"),
                              ("attack_attempts", "test_case_id")]:
            connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})"))
        connection.execute(text(
            "INSERT INTO schema_revisions (revision, applied_at) VALUES (:revision, :now) ON CONFLICT (revision) DO NOTHING"
        ), {"revision": REVISION, "now": datetime.now(timezone.utc).isoformat()})


if __name__ == "__main__":
    from .database import engine
    upgrade(engine)
    print(f"Database upgraded to {REVISION}")
