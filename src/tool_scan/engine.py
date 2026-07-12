from __future__ import annotations

from tool_scan.aggregator import SuppressionSource, aggregate
from tool_scan.collectors.raw_json import RawJsonCollector
from tool_scan.config import ScanConfig
from tool_scan.detectors.heuristic import HeuristicDetector
from tool_scan.findings import Finding
from tool_scan.models import ToolDefinition


def _build_collectors(config: ScanConfig):
    collectors = []
    for source in config.sources:
        if source.type == "raw_json":
            collectors.append(RawJsonCollector(name=source.name, path_glob=source.path))
    return collectors


def _build_detectors(config: ScanConfig):
    detectors = []
    if config.detectors.heuristic.enabled:
        detectors.append(HeuristicDetector(config.detectors.heuristic))
    return detectors


def collect_all(config: ScanConfig) -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    for collector in _build_collectors(config):
        tools.extend(collector.collect())
    return tools


def run_scan(config: ScanConfig, baseline: SuppressionSource | None = None) -> list[Finding]:
    tools = collect_all(config)
    all_findings: list[Finding] = []
    for detector in _build_detectors(config):
        all_findings.extend(detector.scan(tools))
    content_hash_lookup = {t.id: t.content_hash for t in tools}
    return aggregate(
        all_findings,
        ignore_rules=config.ignore_rules,
        baseline=baseline,
        content_hash_lookup=content_hash_lookup,
    )
