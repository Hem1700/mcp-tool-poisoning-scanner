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


def test_docker_sandbox_construction_does_not_import_docker_package(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def _blocking_import(name, *args, **kwargs):
        if name == "docker":
            raise AssertionError("docker package should not be imported during construction")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocking_import)

    from tool_scan.detectors.behavioral import DockerSandbox

    sandbox = DockerSandbox(image="agent-sandbox:latest", network="none")
    config = BehavioralConfig(enabled=True, sandbox=SandboxConfig(image="agent-sandbox:latest"))
    detector = BehavioralProberDetector(config)

    assert isinstance(detector.sandbox, DockerSandbox)


def test_flags_repeated_call_as_unexpected_even_when_name_matches_baseline(tmp_path):
    probe_set = _write_probes(tmp_path, ["repeated_call_probe"])
    baseline_run = _write_baseline(tmp_path, {"repeated_call_probe": ["search_web"]})
    config = BehavioralConfig(
        enabled=True,
        sandbox=SandboxConfig(image="agent-sandbox:latest"),
        probe_set=probe_set,
        baseline_run=baseline_run,
    )
    sandbox = FakeSandbox({"repeated_call_probe": ["search_web", "search_web"]})
    detector = BehavioralProberDetector(config, sandbox=sandbox)
    findings = detector.scan([])
    assert len(findings) == 1
    evidence = findings[0].evidence
    unexpected_portion = evidence.split("unexpected_calls=")[1]
    assert "search_web" in unexpected_portion
