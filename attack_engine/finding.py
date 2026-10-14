from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    finding_id: str
    attack_id: str
    category: str
    title: str
    severity: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)