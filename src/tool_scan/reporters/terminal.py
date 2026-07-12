from __future__ import annotations

from tool_scan.findings import SEVERITY_ORDER, Finding
from tool_scan.reporters.base import Reporter

_SEVERITY_LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


class TerminalReporter(Reporter):
    def render(self, findings: list[Finding]) -> str:
        if not findings:
            return "No findings.\n"

        ordered = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
        lines = [f"{len(findings)} finding(s):", ""]
        for f in ordered:
            label = _SEVERITY_LABELS[f.severity.value]
            lines.append(f"[{label}] {f.tool_name} ({f.source_name}) — {f.detector}")
            lines.append(f"    {f.summary}")
            lines.append(f"    evidence: {f.evidence}")
            lines.append("")
        return "\n".join(lines)
