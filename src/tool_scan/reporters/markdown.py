from __future__ import annotations

from tool_scan.findings import SEVERITY_ORDER, Finding
from tool_scan.reporters.base import Reporter


class MarkdownReporter(Reporter):
    def render(self, findings: list[Finding]) -> str:
        if not findings:
            return "# Tool Poisoning Scan Report\n\nNo findings.\n"

        ordered = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
        lines = ["# Tool Poisoning Scan Report", "", f"{len(findings)} finding(s):", ""]
        for f in ordered:
            lines.append(f"## [{f.severity.value.upper()}] {f.tool_name} ({f.source_name})")
            lines.append("")
            lines.append(f"- **Detector:** {f.detector}")
            lines.append(f"- **Summary:** {f.summary}")
            lines.append(f"- **Evidence:** `{f.evidence}`")
            lines.append(f"- **Confidence:** {f.confidence}")
            lines.append("")
        return "\n".join(lines)
