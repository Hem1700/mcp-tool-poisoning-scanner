from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SourceType(str, Enum):
    MCP = "mcp"
    PYTHON_SCHEMA = "python_schema"
    TS_SCHEMA = "ts_schema"
    RAW_JSON = "raw_json"


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]
    source_type: SourceType
    source_location: str
    source_name: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        digest = hashlib.sha256(f"{self.source_name}:{self.name}".encode("utf-8")).hexdigest()
        return digest[:16]

    @property
    def content_hash(self) -> str:
        digest = hashlib.sha256(self.description.encode("utf-8")).hexdigest()
        return digest[:16]
