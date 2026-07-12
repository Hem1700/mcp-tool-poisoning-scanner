import pytest

from tool_scan.collectors.mcp import McpCollector
from tool_scan.models import SourceType


class FakeTransport:
    def __init__(self, tools: list[dict]) -> None:
        self._tools = tools
        self.last_call: dict | None = None

    def list_tools(self, uri, timeout_seconds, auth_token):
        self.last_call = {"uri": uri, "timeout_seconds": timeout_seconds, "auth_token": auth_token}
        return self._tools


def test_collects_tools_from_fake_transport():
    transport = FakeTransport(
        [{"name": "get_weather", "description": "Fetches weather.", "inputSchema": {}}]
    )
    collector = McpCollector(name="s", uri="http://localhost:8931", transport=transport)
    tools = collector.collect()
    assert len(tools) == 1
    assert tools[0].name == "get_weather"
    assert tools[0].source_type is SourceType.MCP


def test_passes_bearer_token_from_env(monkeypatch):
    monkeypatch.setenv("MY_MCP_TOKEN", "secret-token")
    transport = FakeTransport([])
    collector = McpCollector(name="s", uri="http://x", token_env="MY_MCP_TOKEN", transport=transport)
    collector.collect()
    assert transport.last_call["auth_token"] == "secret-token"


def test_rejects_introspect_only_false():
    with pytest.raises(ValueError, match="introspect_only=False is not supported"):
        McpCollector(name="s", uri="http://x", introspect_only=False)


def test_uses_configured_timeout():
    transport = FakeTransport([])
    collector = McpCollector(name="s", uri="http://x", timeout_seconds=42, transport=transport)
    collector.collect()
    assert transport.last_call["timeout_seconds"] == 42
