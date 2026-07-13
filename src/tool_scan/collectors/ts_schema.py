from __future__ import annotations

import glob
import re
from pathlib import Path

from tool_scan.collectors.base import Collector
from tool_scan.models import SourceType, ToolDefinition

_TOOL_CALL_PATTERN = re.compile(
    r"""\.tool\s*\(\s*["'](?P<name>[^"']+)["']\s*,\s*["'](?P<description>[^"']*)["']""",
    re.DOTALL,
)


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob pattern (supporting **/ as zero-or-more directories,
    bare ** as "anything", * as any characters except /, ? as one character
    except /) into a regex anchored to match a full relative path."""
    parts = []
    i = 0
    n = len(pattern)
    while i < n:
        if pattern[i:i + 3] == "**/":
            parts.append("(?:.*/)?")
            i += 3
        elif pattern[i:i + 2] == "**":
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(parts) + "$")


class TsSchemaCollector(Collector):
    def __init__(
        self,
        name: str,
        root_path: str,
        include_glob: str = "**/*.ts",
        exclude_glob: str | None = None,
    ) -> None:
        self.name = name
        self.root_path = root_path
        self.include_glob = include_glob
        self.exclude_glob = exclude_glob
        self._exclude_regex = _glob_to_regex(exclude_glob) if exclude_glob else None

    def collect(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        pattern = str(Path(self.root_path) / self.include_glob)

        for file_path in sorted(glob.glob(pattern, recursive=True)):
            if self._exclude_regex:
                relative_path = Path(file_path).relative_to(self.root_path).as_posix()
                if self._exclude_regex.match(relative_path):
                    continue
            source = Path(file_path).read_text()
            for match in _TOOL_CALL_PATTERN.finditer(source):
                line_number = source[: match.start()].count("\n") + 1
                tools.append(
                    ToolDefinition(
                        name=match.group("name"),
                        description=match.group("description"),
                        parameters={},
                        source_type=SourceType.TS_SCHEMA,
                        source_location=f"{file_path}:{line_number}",
                        source_name=self.name,
                        raw={"matched_text": match.group(0)},
                    )
                )
        return tools
