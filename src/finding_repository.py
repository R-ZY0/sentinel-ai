import os

import psycopg

from src.finding import Finding


class FindingRepository:
    def __init__(
        self,
        host="localhost",
        port=5432,
        dbname="attack_engine",
        user="postgres",
    ):
        password = os.getenv("POSTGRES_PASSWORD")

        if not password:
            raise ValueError(
                "POSTGRES_PASSWORD environment variable is not set."
            )

        self.connection_string = (
            f"host={host} "
            f"port={port} "
            f"dbname={dbname} "
            f"user={user} "
            f"password={password}"
        )

    def save(self, finding: Finding):
        with psycopg.connect(self.connection_string) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO findings (
                        finding_id,
                        attack_id,
                        category,
                        title,
                        severity,
                        description,
                        evidence,
                        remediation,
                        timestamp
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        finding.finding_id,
                        finding.attack_id,
                        finding.category,
                        finding.title,
                        finding.severity,
                        finding.description,
                        finding.evidence,
                        finding.remediation,
                        finding.timestamp,
                    ),
                )

            connection.commit()