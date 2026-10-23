"""Idempotent Week-01 upgrade for databases created before attack_case_id.

Run after Base.metadata.create_all. Existing attempts remain untouched and
use a NULL case ID until the integrated runner writes definition IDs.
"""
from sqlalchemy import inspect, text


def ensure_attack_case_id_column(engine):
    with engine.begin() as connection:
        columns = {
            column["name"]
            for column in inspect(connection).get_columns("attack_attempts")
        }
        if "attack_case_id" not in columns:
            connection.execute(text(
                "ALTER TABLE attack_attempts ADD COLUMN attack_case_id VARCHAR(100)"
            ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_attack_attempts_attack_case_id "
            "ON attack_attempts (attack_case_id)"
        ))
