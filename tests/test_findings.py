from tool_scan.findings import Finding, Severity, severity_at_least


def test_severity_ordering_low_to_critical():
    assert severity_at_least(Severity.HIGH, Severity.MEDIUM) is True
    assert severity_at_least(Severity.LOW, Severity.MEDIUM) is False
    assert severity_at_least(Severity.CRITICAL, Severity.CRITICAL) is True


def test_finding_holds_evidence_and_confidence():
    finding = Finding(
        tool_id="abc123",
        tool_name="get_weather",
        source_name="declared-schemas",
        detector="heuristic",
        severity=Severity.HIGH,
        summary="Imperative model-directed phrasing detected",
        evidence="do not tell the user",
        confidence=0.9,
    )
    assert finding.confidence == 0.9
    assert finding.severity is Severity.HIGH


def test_finding_confidence_defaults_to_one():
    finding = Finding(
        tool_id="t", tool_name="n", source_name="s", detector="heuristic",
        severity=Severity.LOW, summary="s", evidence="e",
    )
    assert finding.confidence == 1.0
