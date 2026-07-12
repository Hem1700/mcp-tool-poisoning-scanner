from __future__ import annotations

import glob
import json
from pathlib import Path

from tool_scan.collectors.base import Collector
from tool_scan.models import SourceType, ToolDefinition


class RawJsonCollector(Collector):
    def __init__(self, name: str, path_glob: str) -> None:
        self.name = name
        self.path_glob = path_glob

    def collect(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        for file_path in sorted(glob.glob(self.path_glob, recursive=True)):
            raw = json.loads(Path(file_path).read_text())
            entries = raw if isinstance(raw, list) else [raw]
            for entry in entries:
                if not isinstance(entry, dict) or "name" not in entry:
                    # Not a tool definition (e.g. a baseline or other JSON file
                    # incidentally matched by the source glob) — skip it.
                    continue
                tools.append(
                    ToolDefinition(
                        name=entry["name"],
                        description=entry.get("description", ""),
                        parameters=entry.get("parameters", {}),
                        source_type=SourceType.RAW_JSON,
                        source_location=file_path,
                        source_name=self.name,
                        raw=entry,
                    )
                )
        return tools
