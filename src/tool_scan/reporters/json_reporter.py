from __future__ import annotations

import json

from tool_scan.findings import Finding
from tool_scan.reporters.base import Reporter


class JsonReporter(Reporter):
    def render(self, findings: list[Finding]) -> str:
        payload = [
            {
                "tool_id": f.tool_id,
                "tool_name": f.tool_name,
                "source_name": f.source_name,
                "detector": f.detector,
                "severity": f.severity.value,
                "summary": f.summary,
                "evidence": f.evidence,
                "confidence": f.confidence,
            }
            for f in findings
        ]
        return json.dumps(payload, indent=2)
