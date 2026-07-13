from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

import yaml

from tool_scan.config import BehavioralConfig
from tool_scan.detectors.base import Detector
from tool_scan.findings import Finding, Severity
from tool_scan.models import ToolDefinition


@dataclass(frozen=True)
class ProbeResult:
    probe_id: str
    tool_call_sequence: list[str]


class Sandbox(Protocol):
    def run_probe(self, probe_goal: str, timeout_seconds: int) -> ProbeResult: ...


class DockerSandbox:
    def __init__(self, image: str, network: str) -> None:
        self.image = image
        self.network = network

    def run_probe(self, probe_goal: str, timeout_seconds: int) -> ProbeResult:
        import docker

        client = docker.from_env()
        container = client.containers.run(
            self.image, command=["--goal", probe_goal], network_mode=self.network, detach=True
        )
        try:
            container.wait(timeout=timeout_seconds)
            payload = json.loads(container.logs().decode("utf-8"))
            return ProbeResult(probe_id=payload["probe_id"], tool_call_sequence=payload["tool_call_sequence"])
        finally:
            container.remove(force=True)


def _load_probes(path: str) -> list[dict]:
    with open(path) as fh:
        return yaml.safe_load(fh).get("probes", [])


def _load_baseline_trace(path: str) -> dict[str, list[str]]:
    with open(path) as fh:
        data = json.load(fh)
    return {entry["probe_id"]: entry["tool_call_sequence"] for entry in data["traces"]}


class BehavioralProberDetector(Detector):
    name = "behavioral"

    def __init__(self, config: BehavioralConfig, sandbox: Sandbox | None = None) -> None:
        if not config.enabled:
            raise RuntimeError("BehavioralProberDetector constructed while disabled in config")
        self.config = config
        self.sandbox = sandbox or DockerSandbox(image=config.sandbox.image, network=config.sandbox.network)

    def scan(self, tools: list[ToolDefinition]) -> list[Finding]:
        if not self.config.probe_set or not self.config.baseline_run:
            raise RuntimeError("behavioral detector requires probe_set and baseline_run")

        probes = _load_probes(self.config.probe_set)
        baseline_traces = _load_baseline_trace(self.config.baseline_run)

        findings: list[Finding] = []
        for probe in probes:
            result = self.sandbox.run_probe(probe["goal"], self.config.sandbox.timeout_seconds)
            expected = baseline_traces.get(result.probe_id, [])
            if result.tool_call_sequence != expected:
                unexpected_calls = [c for c in result.tool_call_sequence if c not in expected]
                findings.append(
                    Finding(
                        tool_id=probe["id"],
                        tool_name=probe["id"],
                        source_name="behavioral-probe",
                        detector=self.name,
                        severity=Severity.HIGH,
                        summary=(
                            f"Adversarial probe '{result.probe_id}' produced a tool-call "
                            f"sequence that deviates from the benign baseline"
                        ),
                        evidence=(
                            f"expected={expected}, actual={result.tool_call_sequence}, "
                            f"unexpected_calls={unexpected_calls}"
                        ),
                        confidence=0.8,
                    )
                )
        return findings
