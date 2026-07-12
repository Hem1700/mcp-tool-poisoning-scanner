from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

from tool_scan.config import HeuristicConfig, HeuristicRule
from tool_scan.detectors.base import Detector
from tool_scan.findings import Finding, Severity
from tool_scan.models import ToolDefinition


@dataclass(frozen=True)
class CompiledRule:
    id: str
    pattern: re.Pattern[str]
    description: str
    severity: Severity


def _compile_rule(rule: HeuristicRule) -> CompiledRule:
    return CompiledRule(
        id=rule.id,
        pattern=re.compile(rule.pattern, re.IGNORECASE),
        description=rule.description,
        severity=Severity(rule.severity),
    )


def load_rule_pack(path: str) -> list[HeuristicRule]:
    with open(path) as fh:
        raw = yaml.safe_load(fh)
    return [HeuristicRule(**entry) for entry in raw.get("rules", [])]


class HeuristicDetector(Detector):
    name = "heuristic"

    def __init__(self, config: HeuristicConfig) -> None:
        rules: list[HeuristicRule] = list(config.rules)
        for pack_path in config.rule_packs:
            rules.extend(load_rule_pack(pack_path))
        self._compiled = [_compile_rule(r) for r in rules]

    def scan(self, tools: list[ToolDefinition]) -> list[Finding]:
        findings: list[Finding] = []
        for tool in tools:
            for rule in self._compiled:
                match = rule.pattern.search(tool.description)
                if match:
                    findings.append(
                        Finding(
                            tool_id=tool.id,
                            tool_name=tool.name,
                            source_name=tool.source_name,
                            detector=self.name,
                            severity=rule.severity,
                            summary=rule.description,
                            evidence=match.group(0),
                            confidence=1.0,
                        )
                    )
        return findings
