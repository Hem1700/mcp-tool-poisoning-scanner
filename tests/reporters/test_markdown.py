from tool_scan.findings import Finding, Severity
from tool_scan.reporters.markdown import MarkdownReporter


def test_renders_no_findings_heading():
    output = MarkdownReporter().render([])
    assert "No findings" in output
    assert output.startswith("# Tool Poisoning Scan Report")


def test_renders_finding_as_markdown_section():
    finding = Finding(
        tool_id="t1", tool_name="get_weather", source_name="s",
        detector="heuristic", severity=Severity.CRITICAL,
        summary="Sensitive path reference", evidence="~/.ssh/id_rsa", confidence=1.0,
    )
    output = MarkdownReporter().render([finding])
    assert "## [CRITICAL] get_weather (s)" in output
    assert "**Detector:** heuristic" in output
    assert "`~/.ssh/id_rsa`" in output
