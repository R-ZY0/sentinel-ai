from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Literal


EvaluationStatus = Literal["pending", "pass", "fail", "not_evaluated"]


@dataclass
class AttackRun:
    attack_id: str
    category: str
    payload: str
    target: str
    strategy: str
    expected_behavior: str
    actual_response: Optional[str] = None
    status: str = "pending"
    passed: Optional[bool] = None
    evaluation_status: EvaluationStatus = "pending"
    judge_reason: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    execution_error: Optional[str] = None
    mutation_strategy: Optional[str] = None
