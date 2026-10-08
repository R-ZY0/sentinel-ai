import logging
from uuid import UUID

logger = logging.getLogger(__name__)


class AttackRunner:
    def run(self, scan_id: UUID, target_id: UUID) -> dict:
        logger.info(
            "AttackRunner dry run: scan=%s target=%s",
            scan_id,
            target_id,
        )

        return {
            "mode": "dry_run",
            "scan_id": str(scan_id),
            "target_id": str(target_id),
            "attacks_executed": 0,
        }