from __future__ import annotations

import json

from tool_scan.findings import Finding
from tool_scan.reporters.base import Reporter

_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "warning", "critical": "error"}


class SarifReporter(Reporter):
    def render(self, findings: list[Finding]) -> str:
        rule_ids = sorted({f.detector for f in findings})
        rules = [{"id": rule_id, "name": rule_id} for rule_id in rule_ids]

        results = [
            {
                "ruleId": f.detector,
                "level": _SARIF_LEVEL[f.severity.value],
                "message": {"text": f"{f.summary} (evidence: {f.evidence})"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f.source_name}}}
                ],
                "properties": {
                    "tool_id": f.tool_id,
                    "tool_name": f.tool_name,
                    "confidence": f.confidence,
                },
            }
            for f in findings
        ]

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "mcp-tool-poisoning-scanner", "rules": rules}},
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)
