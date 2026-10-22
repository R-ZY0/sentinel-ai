from dataclasses import dataclass

from .attack_library import ATTACK_LIBRARY


@dataclass(frozen=True)
class Probe:
    category: str
    payload: str


class AttackEngine:
    def probes(self) -> list[Probe]:
        return [
            Probe(
                category=attack.category,
                payload=attack.payload,
            )
            for attack in ATTACK_LIBRARY
        ]
