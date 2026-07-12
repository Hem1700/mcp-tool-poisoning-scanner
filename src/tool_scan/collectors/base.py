from __future__ import annotations

from abc import ABC, abstractmethod

from tool_scan.models import ToolDefinition


class Collector(ABC):
    @abstractmethod
    def collect(self) -> list[ToolDefinition]:
        """Return every ToolDefinition this collector can find."""
