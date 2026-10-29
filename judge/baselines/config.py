"""Local baseline configuration; not a shared schema."""
from dataclasses import dataclass


@dataclass(frozen=True)
class BaselineConfig:
    canaries: tuple[str, ...] = ()
    regex_patterns: tuple[str, ...] = ()
    presidio_score_threshold: float = 0.35
    llm_model: str = "llama3.2:3b"
    llm_host: str = "http://localhost:11434"

    def __post_init__(self) -> None:
        if not 0 <= self.presidio_score_threshold <= 1:
            raise ValueError("presidio_score_threshold must be between 0 and 1")
