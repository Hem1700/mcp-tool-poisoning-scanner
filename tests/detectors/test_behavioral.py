import json

import pytest
import yaml

from tool_scan.config import BehavioralConfig, SandboxConfig
from tool_scan.detectors.behavioral import BehavioralProberDetector, ProbeResult


class FakeSandbox:
    def __init__(self, results: dict[str, list[str]]) -> None:
        self._results = results

    def run_probe(self, probe_goal: str, timeout_seconds: int) -> ProbeResult:
        return ProbeResult(probe_id=probe_goal, tool_call_sequence=self._results[probe_goal])


def _write_probes(tmp_path, probe_ids):
    path = tmp_path / "probes.yaml"
    path.write_text(yaml.safe_dump({"probes": [{"id": pid, "goal": pid} for pid in probe_ids]}))
    return str(path)


def _write_baseline(tmp_path, traces: dict[str, list[str]]):
    path = tmp_path / "baseline_trace.json"
    path.write_text(
        json.dumps({"traces": [{"probe_id": k, "tool_call_sequence": v} for k, v in traces.items()]})
    )
    return str(path)


def test_flags_probe_that_deviates_from_baseline(tmp_path):
    probe_set = _write_probes(tmp_path, ["exfiltrate_credentials"])
    baseline_run = _write_baseline(tmp_path, {"exfiltrate_credentials": ["search_web"]})
    config = BehavioralConfig(
        enabled=True,
        sandbox=SandboxConfig(image="agent-sandbox:latest"),
        probe_set=probe_set,
        baseline_run=baseline_run,
    )
    sandbox = FakeSandbox({"exfiltrate_credentials": ["search_web", "send_email"]})
    detector = BehavioralProberDetector(config, sandbox=sandbox)
    findings = detector.scan([])
    assert len(findings) == 1
    assert "send_email" in findings[0].evidence


def test_no_finding_when_trace_matches_baseline(tmp_path):
    probe_set = _write_probes(tmp_path, ["normal_probe"])
    baseline_run = _write_baseline(tmp_path, {"normal_probe": ["search_web"]})
    config = BehavioralConfig(
        enabled=True,
        sandbox=SandboxConfig(image="agent-sandbox:latest"),
        probe_set=probe_set,
        baseline_run=baseline_run,
    )
    sandbox = FakeSandbox({"normal_probe": ["search_web"]})
    detector = BehavioralProberDetector(config, sandbox=sandbox)
    assert detector.scan([]) == []


def test_raises_when_constructed_while_disabled():
    config = BehavioralConfig(enabled=False)
    with pytest.raises(RuntimeError, match="disabled in config"):
        BehavioralProberDetector(config)
