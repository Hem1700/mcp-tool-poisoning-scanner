from __future__ import annotations

from abc import ABC, abstractmethod

from tool_scan.findings import Finding
from tool_scan.models import ToolDefinition


class Detector(ABC):
    name: str

    @abstractmethod
    def scan(self, tools: list[ToolDefinition]) -> list[Finding]:
        """Return every Finding this detector produces for the given tools."""
