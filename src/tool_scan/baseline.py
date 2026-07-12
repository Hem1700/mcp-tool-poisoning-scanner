from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BaselineEntry:
    content_hash: str
    reviewer_note: str
    approved_date: str


class Baseline:
    def __init__(self, entries: dict[str, BaselineEntry] | None = None) -> None:
        self._entries = entries or {}

    def is_suppressed(self, tool_id: str, content_hash: str) -> bool:
        entry = self._entries.get(tool_id)
        return entry is not None and entry.content_hash == content_hash

    def approve(self, tool_id: str, content_hash: str, reviewer_note: str, approved_date: str) -> None:
        self._entries[tool_id] = BaselineEntry(
            content_hash=content_hash, reviewer_note=reviewer_note, approved_date=approved_date
        )

    def to_dict(self) -> dict:
        return {
            tool_id: {
                "content_hash": e.content_hash,
                "reviewer_note": e.reviewer_note,
                "approved_date": e.approved_date,
            }
            for tool_id, e in self._entries.items()
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        return cls({tool_id: BaselineEntry(**fields) for tool_id, fields in data.items()})

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path)
        if not p.exists():
            return cls()
        return cls.from_dict(json.loads(p.read_text()))
