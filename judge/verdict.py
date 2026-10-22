from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    LEAK = "LEAK"
    NO_LEAK = "NO_LEAK"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(slots=True)
class JudgeVerdict:
    verdict: Verdict
    confidence: float
    reason: str
    signals: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "signals": self.signals,
        }
