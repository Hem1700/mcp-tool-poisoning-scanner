from __future__ import annotations

import os
from typing import Protocol

from tool_scan.collectors.base import Collector
from tool_scan.models import SourceType, ToolDefinition


class McpTransport(Protocol):
    def list_tools(self, uri: str, timeout_seconds: int, auth_token: str | None) -> list[dict]: ...


class RealMcpTransport:
    def list_tools(self, uri: str, timeout_seconds: int, auth_token: str | None) -> list[dict]:
        import anyio
        from mcp import ClientSession
        from mcp.client.sse import sse_client

        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None

        async def _fetch() -> list[dict]:
            async with sse_client(uri, headers=headers, timeout=timeout_seconds) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    return [
                        {"name": t.name, "description": t.description or "", "inputSchema": t.inputSchema}
                        for t in result.tools
                    ]

        return anyio.run(_fetch)


class McpCollector(Collector):
    def __init__(
        self,
        name: str,
        uri: str,
        introspect_only: bool = True,
        timeout_seconds: int = 10,
        token_env: str | None = None,
        transport: McpTransport | None = None,
    ) -> None:
        if not introspect_only:
            raise ValueError(
                "introspect_only=False is not supported: the mcp collector must never "
                "invoke tools during a scan"
            )
        self.name = name
        self.uri = uri
        self.timeout_seconds = timeout_seconds
        self.token_env = token_env
        self.transport = transport or RealMcpTransport()

    def collect(self) -> list[ToolDefinition]:
        auth_token = os.environ.get(self.token_env) if self.token_env else None
        raw_tools = self.transport.list_tools(self.uri, self.timeout_seconds, auth_token)
        return [
            ToolDefinition(
                name=t["name"],
                description=t.get("description", ""),
                parameters=t.get("inputSchema", {}),
                source_type=SourceType.MCP,
                source_location=self.uri,
                source_name=self.name,
                raw=t,
            )
            for t in raw_tools
        ]
