from tool_scan.collectors.python_schema import PythonSchemaCollector


def test_collects_decorated_function_with_docstring(tmp_path):
    module = tmp_path / "tools.py"
    module.write_text(
        '''
from mytools import tool


@tool
def get_weather(city: str) -> str:
    """Fetches current weather for a city."""
    return "sunny"


def not_a_tool(x: int) -> int:
    """Should not be collected."""
    return x
'''
    )
    collector = PythonSchemaCollector(name="backend-tools", root_path=str(tmp_path))
    tools = collector.collect()

    assert len(tools) == 1
    assert tools[0].name == "get_weather"
    assert tools[0].description == "Fetches current weather for a city."
    assert "city" in tools[0].parameters["properties"]


def test_collects_call_style_decorator(tmp_path):
    module = tmp_path / "tools.py"
    module.write_text(
        '''
import mcp


@mcp.tool()
def search(query: str) -> str:
    """Searches the web."""
    return ""
'''
    )
    collector = PythonSchemaCollector(name="s", root_path=str(tmp_path))
    tools = collector.collect()
    assert tools[0].name == "search"


def test_source_location_includes_file_and_line(tmp_path):
    module = tmp_path / "tools.py"
    module.write_text(
        '''
from mytools import tool


@tool
def get_weather(city: str) -> str:
    """Fetches weather."""
    return ""
'''
    )
    collector = PythonSchemaCollector(name="s", root_path=str(tmp_path))
    tools = collector.collect()
    assert str(module) in tools[0].source_location
    assert ":" in tools[0].source_location.split(str(module))[1]


def test_exclude_glob_skips_matching_files(tmp_path):
    keep = tmp_path / "tools.py"
    keep.write_text(
        '''
from mytools import tool


@tool
def get_weather(city: str) -> str:
    """Fetches weather."""
    return ""
'''
    )
    skip = tmp_path / "tools_test.py"
    skip.write_text(
        '''
from mytools import tool


@tool
def fake_tool_for_testing(x: str) -> str:
    """Should be excluded."""
    return ""
'''
    )
    collector = PythonSchemaCollector(
        name="s", root_path=str(tmp_path), exclude_glob="**/*_test.py"
    )
    tools = collector.collect()
    assert {t.name for t in tools} == {"get_weather"}
