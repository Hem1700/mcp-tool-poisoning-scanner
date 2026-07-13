from __future__ import annotations

from itertools import product

from tool_scan.config import TaintConfig
from tool_scan.detectors.base import Detector
from tool_scan.findings import Finding, Severity
from tool_scan.models import ToolDefinition


class TaintGraphDetector(Detector):
    name = "taint"

    def __init__(self, config: TaintConfig) -> None:
        if config.mode == "dynamic":
            raise NotImplementedError(
                "dynamic taint mode requires trace_source ingestion, not yet implemented"
            )
        self.config = config

    def scan(self, tools: list[ToolDefinition]) -> list[Finding]:
        low_trust_names = set(self.config.trust_tiers.low_trust)
        high_trust_names = set(self.config.trust_tiers.high_trust)

        low_trust_tools = [t for t in tools if t.name in low_trust_names]
        high_trust_tools = [t for t in tools if t.name in high_trust_names]

        findings: list[Finding] = []
        for low, high in product(low_trust_tools, high_trust_tools):
            if low.source_name != high.source_name:
                continue
            findings.append(
                Finding(
                    tool_id=high.id,
                    tool_name=high.name,
                    source_name=high.source_name,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    summary=(
                        f"Structural taint path: low-trust tool '{low.name}' and high-trust "
                        f"tool '{high.name}' are both available to the same agent, with no "
                        f"declared trust boundary between them"
                    ),
                    evidence=f"low_trust={low.name}, high_trust={high.name}",
                    confidence=0.5,
                )
            )
        return findings
