from __future__ import annotations

import ast
import glob
from pathlib import Path

from tool_scan.collectors.base import Collector
from tool_scan.models import SourceType, ToolDefinition

_TOOL_DECORATOR_NAMES = {"tool"}


def _decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def _is_tool_decorated(func: ast.FunctionDef) -> bool:
    return any(_decorator_name(dec) in _TOOL_DECORATOR_NAMES for dec in func.decorator_list)


def _extract_parameters(func: ast.FunctionDef) -> dict:
    properties = {}
    for arg in func.args.args:
        if arg.arg == "self":
            continue
        type_name = ast.unparse(arg.annotation) if arg.annotation else "Any"
        properties[arg.arg] = {"type": type_name}
    return {"type": "object", "properties": properties}


class PythonSchemaCollector(Collector):
    def __init__(
        self,
        name: str,
        root_path: str,
        include_glob: str = "**/*.py",
        exclude_glob: str | None = None,
    ) -> None:
        self.name = name
        self.root_path = root_path
        self.include_glob = include_glob
        self.exclude_glob = exclude_glob

    def collect(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        pattern = str(Path(self.root_path) / self.include_glob)

        for file_path in sorted(glob.glob(pattern, recursive=True)):
            file_path_obj = Path(file_path)
            # Use Path.match() for exclude_glob to support ** patterns
            if self.exclude_glob and file_path_obj.match(self.exclude_glob):
                continue
            source = Path(file_path).read_text()
            tree = ast.parse(source, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and _is_tool_decorated(node):
                    docstring = ast.get_docstring(node) or ""
                    tools.append(
                        ToolDefinition(
                            name=node.name,
                            description=docstring,
                            parameters=_extract_parameters(node),
                            source_type=SourceType.PYTHON_SCHEMA,
                            source_location=f"{file_path}:{node.lineno}",
                            source_name=self.name,
                            raw={"docstring": docstring, "args": [a.arg for a in node.args.args]},
                        )
                    )
        return tools
