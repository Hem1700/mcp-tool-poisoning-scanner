from __future__ import annotations

from collections import defaultdict
from typing import Protocol

from tool_scan.config import IgnoreRule
from tool_scan.findings import SEVERITY_ORDER, Finding


class SuppressionSource(Protocol):
    def is_suppressed(self, tool_id: str, content_hash: str) -> bool: ...


def _is_ignored(finding: Finding, ignore_rules: list[IgnoreRule]) -> bool:
    for rule in ignore_rules:
        if rule.match.source == finding.source_name and rule.match.tool_name == finding.tool_name:
            return True
    return False


def _combine_confidence(confidences: list[float]) -> float:
    product = 1.0
    for c in confidences:
        product *= 1.0 - c
    return round(1.0 - product, 4)


def _merge_findings_for_tool(tool_id: str, findings: list[Finding]) -> Finding:
    if len(findings) == 1:
        return findings[0]
    detectors = sorted({f.detector for f in findings})
    max_severity = max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
    combined_confidence = _combine_confidence([f.confidence for f in findings])
    evidence = "; ".join(f"[{f.detector}] {f.evidence}" for f in findings)
    summary = "; ".join(sorted({f.summary for f in findings}))
    first = findings[0]
    return Finding(
        tool_id=tool_id,
        tool_name=first.tool_name,
        source_name=first.source_name,
        detector="+".join(detectors),
        severity=max_severity,
        summary=summary,
        evidence=evidence,
        confidence=combined_confidence,
    )


def aggregate(
    findings: list[Finding],
    ignore_rules: list[IgnoreRule] | None = None,
    baseline: SuppressionSource | None = None,
    content_hash_lookup: dict[str, str] | None = None,
) -> list[Finding]:
    ignore_rules = ignore_rules or []
    content_hash_lookup = content_hash_lookup or {}

    surviving = [f for f in findings if not _is_ignored(f, ignore_rules)]

    if baseline is not None:
        surviving = [
            f
            for f in surviving
            if not baseline.is_suppressed(f.tool_id, content_hash_lookup.get(f.tool_id, ""))
        ]

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in surviving:
        grouped[f.tool_id].append(f)

    return [_merge_findings_for_tool(tool_id, group) for tool_id, group in grouped.items()]
