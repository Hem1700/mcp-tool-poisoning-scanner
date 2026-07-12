from __future__ import annotations

from abc import ABC, abstractmethod

from tool_scan.findings import Finding


class Reporter(ABC):
    @abstractmethod
    def render(self, findings: list[Finding]) -> str:
        """Return a rendered report string for the given findings."""
