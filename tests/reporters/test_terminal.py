from tool_scan.findings import Finding, Severity
from tool_scan.reporters.terminal import TerminalReporter


def test_renders_no_findings_message():
    assert TerminalReporter().render([]) == "No findings.\n"


def test_renders_findings_sorted_by_severity_descending():
    low = Finding(
        tool_id="t1", tool_name="a", source_name="s", detector="heuristic",
        severity=Severity.LOW, summary="low issue", evidence="e",
    )
    critical = Finding(
        tool_id="t2", tool_name="b", source_name="s", detector="heuristic",
        severity=Severity.CRITICAL, summary="critical issue", evidence="e",
    )
    output = TerminalReporter().render([low, critical])
    assert output.index("CRITICAL") < output.index("LOW")


def test_includes_tool_name_summary_and_evidence():
    finding = Finding(
        tool_id="t1", tool_name="get_weather", source_name="declared-schemas",
        detector="heuristic", severity=Severity.HIGH,
        summary="Model-directed imperative phrasing", evidence="do not tell the user",
    )
    output = TerminalReporter().render([finding])
    assert "get_weather" in output
    assert "declared-schemas" in output
    assert "Model-directed imperative phrasing" in output
    assert "do not tell the user" in output
