from tool_scan.collectors.ts_schema import TsSchemaCollector


def test_collects_tool_registration_call(tmp_path):
    ts_file = tmp_path / "tools.ts"
    ts_file.write_text(
        '''
server.tool("get_weather", "Fetches current weather for a city.", async (args) => {
  return "sunny";
});
'''
    )
    collector = TsSchemaCollector(name="frontend-agent-tools", root_path=str(tmp_path))
    tools = collector.collect()
    assert len(tools) == 1
    assert tools[0].name == "get_weather"
    assert tools[0].description == "Fetches current weather for a city."


def test_collects_multiple_registrations_in_one_file(tmp_path):
    ts_file = tmp_path / "tools.ts"
    ts_file.write_text(
        '''
server.tool("tool_a", "Description A", handlerA);
server.tool("tool_b", "Description B", handlerB);
'''
    )
    collector = TsSchemaCollector(name="s", root_path=str(tmp_path))
    tools = collector.collect()
    assert {t.name for t in tools} == {"tool_a", "tool_b"}


def test_source_location_includes_line_number(tmp_path):
    ts_file = tmp_path / "tools.ts"
    ts_file.write_text('\n\nserver.tool("get_weather", "Fetches weather.", handler);\n')
    collector = TsSchemaCollector(name="s", root_path=str(tmp_path))
    tools = collector.collect()
    assert tools[0].source_location.endswith(":3")


def test_exclude_glob_skips_matching_files(tmp_path):
    keep = tmp_path / "tools.ts"
    keep.write_text('server.tool("get_weather", "Fetches weather.", handler);\n')
    skip = tmp_path / "tools_test.ts"
    skip.write_text('server.tool("fake_tool", "Excluded.", handler);\n')
    collector = TsSchemaCollector(name="s", root_path=str(tmp_path), exclude_glob="**/*_test.ts")
    tools = collector.collect()
    assert {t.name for t in tools} == {"get_weather"}
