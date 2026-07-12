import dataclasses

import pytest

from tool_scan.models import SourceType, ToolDefinition


def test_id_is_stable_for_same_source_and_name():
    a = ToolDefinition(
        name="get_weather",
        description="Fetches current weather for a city.",
        parameters={"type": "object", "properties": {}},
        source_type=SourceType.RAW_JSON,
        source_location="schemas/weather.json",
        source_name="declared-schemas",
    )
    b = ToolDefinition(
        name="get_weather",
        description="A completely different description.",
        parameters={"type": "object", "properties": {}},
        source_type=SourceType.RAW_JSON,
        source_location="schemas/weather.json",
        source_name="declared-schemas",
    )
    assert a.id == b.id  # id depends on source_name + name, not description


def test_content_hash_changes_when_description_changes():
    base_kwargs = dict(
        name="get_weather",
        parameters={},
        source_type=SourceType.RAW_JSON,
        source_location="schemas/weather.json",
        source_name="declared-schemas",
    )
    a = ToolDefinition(description="Fetches current weather.", **base_kwargs)
    b = ToolDefinition(description="Fetches current weather for a city.", **base_kwargs)
    assert a.content_hash != b.content_hash


def test_id_differs_across_sources_with_same_tool_name():
    kwargs = dict(
        name="search",
        description="Searches the web.",
        parameters={},
        source_type=SourceType.RAW_JSON,
    )
    a = ToolDefinition(source_location="a.json", source_name="source-a", **kwargs)
    b = ToolDefinition(source_location="b.json", source_name="source-b", **kwargs)
    assert a.id != b.id


def test_tool_definition_is_immutable():
    tool = ToolDefinition(
        name="x",
        description="y",
        parameters={},
        source_type=SourceType.RAW_JSON,
        source_location="z.json",
        source_name="s",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        tool.name = "changed"
