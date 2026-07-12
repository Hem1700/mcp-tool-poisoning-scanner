from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


@dataclass(frozen=True)
class Finding:
    tool_id: str
    tool_name: str
    source_name: str
    detector: str
    severity: Severity
    summary: str
    evidence: str
    confidence: float = 1.0
