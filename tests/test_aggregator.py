from tool_scan.aggregator import aggregate
from tool_scan.config import IgnoreMatch, IgnoreRule
from tool_scan.findings import Finding, Severity


def _finding(
    detector: str,
    severity: Severity,
    confidence: float = 1.0,
    tool_id: str = "t1",
    tool_name: str = "get_weather",
    source_name: str = "s",
) -> Finding:
    return Finding(
        tool_id=tool_id,
        tool_name=tool_name,
        source_name=source_name,
        detector=detector,
        severity=severity,
        summary=f"{detector} finding",
        evidence="evidence",
        confidence=confidence,
    )


def test_passes_through_single_finding_unchanged():
    findings = [_finding("heuristic", Severity.HIGH)]
    assert aggregate(findings) == findings


def test_merges_multiple_detector_findings_for_same_tool():
    findings = [
        _finding("heuristic", Severity.MEDIUM, confidence=0.7),
        _finding("ml_anomaly", Severity.HIGH, confidence=0.6),
    ]
    result = aggregate(findings)
    assert len(result) == 1
    merged = result[0]
    assert merged.severity == Severity.HIGH
    assert merged.detector == "heuristic+ml_anomaly"
    assert merged.confidence > 0.7


def test_applies_ignore_rule_by_source_and_tool_name():
    findings = [_finding("heuristic", Severity.HIGH, tool_name="debug_echo", source_name="s")]
    ignore_rules = [
        IgnoreRule(
            match=IgnoreMatch(source="s", tool_name="debug_echo"),
            reason="Internal test tool, reviewed 2026-07-11",
        )
    ]
    assert aggregate(findings, ignore_rules=ignore_rules) == []


def test_applies_baseline_suppression():
    class FakeBaseline:
        def is_suppressed(self, tool_id: str, content_hash: str) -> bool:
            return tool_id == "t1" and content_hash == "approved-hash"

    findings = [_finding("heuristic", Severity.HIGH, tool_id="t1")]
    result = aggregate(
        findings, baseline=FakeBaseline(), content_hash_lookup={"t1": "approved-hash"}
    )
    assert result == []


def test_different_tools_are_not_merged():
    findings = [
        _finding("heuristic", Severity.HIGH, tool_id="t1"),
        _finding("heuristic", Severity.HIGH, tool_id="t2"),
    ]
    assert len(aggregate(findings)) == 2
