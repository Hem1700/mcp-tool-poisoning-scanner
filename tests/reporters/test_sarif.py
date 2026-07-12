import json

from tool_scan.findings import Finding, Severity
from tool_scan.reporters.sarif import SarifReporter


def test_renders_valid_sarif_structure_for_empty_findings():
    parsed = json.loads(SarifReporter().render([]))
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"] == []


def test_maps_critical_severity_to_sarif_error_level():
    finding = Finding(
        tool_id="t1", tool_name="get_weather", source_name="s",
        detector="heuristic", severity=Severity.CRITICAL,
        summary="Sensitive path reference", evidence="~/.ssh/id_rsa",
    )
    parsed = json.loads(SarifReporter().render([finding]))
    result = parsed["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["ruleId"] == "heuristic"
    assert "~/.ssh/id_rsa" in result["message"]["text"]


def test_maps_low_severity_to_sarif_note_level():
    finding = Finding(
        tool_id="t1", tool_name="x", source_name="s", detector="heuristic",
        severity=Severity.LOW, summary="minor", evidence="e",
    )
    parsed = json.loads(SarifReporter().render([finding]))
    assert parsed["runs"][0]["results"][0]["level"] == "note"


def test_deduplicates_rule_ids_in_driver_rules():
    findings = [
        Finding(tool_id="t1", tool_name="a", source_name="s", detector="heuristic",
                severity=Severity.HIGH, summary="s1", evidence="e1"),
        Finding(tool_id="t2", tool_name="b", source_name="s", detector="heuristic",
                severity=Severity.HIGH, summary="s2", evidence="e2"),
    ]
    parsed = json.loads(SarifReporter().render(findings))
    assert len(parsed["runs"][0]["tool"]["driver"]["rules"]) == 1
