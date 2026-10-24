"""Week-01 attack selection backed by Cyber #1's shared library."""
from dataclasses import dataclass
import os
from attack_engine.attack_library import ATTACK_LIBRARY


@dataclass(frozen=True)
class Probe:
    attack_case_id: str
    category: str
    payload: str
    strategy: str
    expected_behavior: str


class AttackEngine:
    """Select authorized local test cases; preserve Week-1 default behaviour.

    SENTINEL_SCAN_PROFILE=full_local is explicitly opt-in. Any other value
    fails closed rather than silently downgrading to a one-case smoke test.
    """

    ALLOWED_PROFILES = frozenset({"week1_local", "full_local"})

    def __init__(self, profile: str | None = None):
        self.profile = (
            profile if profile is not None
            else os.environ.get("SENTINEL_SCAN_PROFILE", "week1_local")
        )
        if self.profile not in self.ALLOWED_PROFILES:
            raise ValueError("Unsupported SENTINEL_SCAN_PROFILE")

    def probes(self) -> list[Probe]:
        if self.profile == "week1_local":
            cases = [next(item for item in ATTACK_LIBRARY if item.attack_id == "SPL-001")]
        else:
            cases = ATTACK_LIBRARY
        return [
            Probe(
                attack_case_id=case.attack_id,
                category=case.category,
                payload=case.payload,
                strategy=case.strategy,
                expected_behavior=case.expected_behavior,
            )
            for case in cases
        ]
