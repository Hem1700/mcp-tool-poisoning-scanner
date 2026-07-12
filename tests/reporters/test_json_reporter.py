import json

from tool_scan.findings import Finding, Severity
from tool_scan.reporters.json_reporter import JsonReporter


def test_renders_empty_list_as_empty_json_array():
    assert json.loads(JsonReporter().render([])) == []


def test_renders_finding_fields_as_json():
    finding = Finding(
        tool_id="t1", tool_name="get_weather", source_name="s",
        detector="heuristic", severity=Severity.CRITICAL,
        summary="Sensitive path reference", evidence="~/.ssh/id_rsa", confidence=1.0,
    )
    parsed = json.loads(JsonReporter().render([finding]))
    assert parsed == [
        {
            "tool_id": "t1",
            "tool_name": "get_weather",
            "source_name": "s",
            "detector": "heuristic",
            "severity": "critical",
            "summary": "Sensitive path reference",
            "evidence": "~/.ssh/id_rsa",
            "confidence": 1.0,
        }
    ]
