"""Week-01 attack selection backed by Cyber #1's shared library."""
from dataclasses import dataclass
from attack_engine.attack_library import ATTACK_LIBRARY


@dataclass(frozen=True)
class Probe:
    attack_case_id: str
    category: str
    payload: str
    strategy: str
    expected_behavior: str


class AttackEngine:
    def probes(self) -> list[Probe]:
        # P0 acceptance runs one deterministic, authorized local scenario.
        # A later full-suite integration will select all 15 cases.
        case = next(item for item in ATTACK_LIBRARY if item.attack_id == "SPL-001")
        return [Probe(
            attack_case_id=case.attack_id,
            category=case.category,
            payload=case.payload,
            strategy=case.strategy,
            expected_behavior=case.expected_behavior,
        )]
