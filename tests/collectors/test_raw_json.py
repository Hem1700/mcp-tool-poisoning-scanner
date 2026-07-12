import json

from tool_scan.collectors.raw_json import RawJsonCollector
from tool_scan.models import SourceType


def test_collects_single_tool_json_file(tmp_path):
    tool_file = tmp_path / "weather.json"
    tool_file.write_text(
        json.dumps(
            {
                "name": "get_weather",
                "description": "Fetches current weather for a city.",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
            }
        )
    )
    collector = RawJsonCollector(name="declared-schemas", path_glob=str(tmp_path / "*.json"))
    tools = collector.collect()

    assert len(tools) == 1
    assert tools[0].name == "get_weather"
    assert tools[0].source_type is SourceType.RAW_JSON
    assert tools[0].source_name == "declared-schemas"


def test_collects_list_of_tools_from_one_file(tmp_path):
    tool_file = tmp_path / "tools.json"
    tool_file.write_text(
        json.dumps(
            [
                {"name": "tool_a", "description": "A", "parameters": {}},
                {"name": "tool_b", "description": "B", "parameters": {}},
            ]
        )
    )
    collector = RawJsonCollector(name="s", path_glob=str(tmp_path / "*.json"))
    tools = collector.collect()
    assert {t.name for t in tools} == {"tool_a", "tool_b"}


def test_returns_empty_list_when_no_files_match(tmp_path):
    collector = RawJsonCollector(name="s", path_glob=str(tmp_path / "*.json"))
    assert collector.collect() == []


def test_preserves_raw_payload_for_evidence(tmp_path):
    tool_file = tmp_path / "weather.json"
    payload = {"name": "get_weather", "description": "Fetches weather.", "parameters": {}}
    tool_file.write_text(json.dumps(payload))
    collector = RawJsonCollector(name="s", path_glob=str(tmp_path / "*.json"))
    tools = collector.collect()
    assert tools[0].raw == payload


def test_skips_json_files_that_are_not_tool_definitions(tmp_path):
    tool_file = tmp_path / "weather.json"
    tool_file.write_text(
        json.dumps({"name": "get_weather", "description": "Fetches weather.", "parameters": {}})
    )
    # Non-tool JSON living alongside tool files (e.g. a baseline file written into
    # the same scanned directory) must not crash the collector.
    other_file = tmp_path / "baseline.json"
    other_file.write_text(json.dumps({"some_tool_id": {"content_hash": "abc"}}))

    collector = RawJsonCollector(name="s", path_glob=str(tmp_path / "*.json"))
    tools = collector.collect()

    assert [t.name for t in tools] == ["get_weather"]
