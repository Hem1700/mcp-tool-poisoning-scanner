from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class ConfigError(Exception):
    """Raised for structurally or semantically invalid scan configuration."""


# ── Sources ─────────────────────────────────────────────────────────

class McpAuth(BaseModel):
    type: Literal["bearer"] = "bearer"
    token_env: str


class McpSource(BaseModel):
    type: Literal["mcp"]
    name: str
    uri: str
    introspect_only: bool = True
    timeout_seconds: int = 10
    auth: McpAuth | None = None


class PythonSchemaSource(BaseModel):
    type: Literal["python_schema"]
    name: str
    path: str
    include_glob: str = "**/*.py"
    exclude_glob: str | None = None


class TsSchemaSource(BaseModel):
    type: Literal["ts_schema"]
    name: str
    path: str
    include_glob: str = "**/*.ts"
    exclude_glob: str | None = None


class RawJsonSource(BaseModel):
    type: Literal["raw_json"]
    name: str
    path: str


SourceConfig = Annotated[
    Union[McpSource, PythonSchemaSource, TsSchemaSource, RawJsonSource],
    Field(discriminator="type"),
]


# ── Detectors ───────────────────────────────────────────────────────

class HeuristicRule(BaseModel):
    id: str
    pattern: str
    description: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"


class HeuristicConfig(BaseModel):
    enabled: bool = True
    rule_packs: list[str] = Field(default_factory=list)
    rules: list[HeuristicRule] = Field(default_factory=list)


class LLMJudgeConfig(BaseModel):
    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-sonnet-5"
    api_key_env: str = "ANTHROPIC_API_KEY"
    temperature: float = 0.0
    confidence_threshold: float = 0.6
    max_calls_per_scan: int = 200
    prompt_template: str | None = None


class TrustTiers(BaseModel):
    low_trust: list[str] = Field(default_factory=list)
    high_trust: list[str] = Field(default_factory=list)


class TaintConfig(BaseModel):
    enabled: bool = True
    mode: Literal["static", "dynamic"] = "static"
    trace_source: str | None = None
    trust_tiers: TrustTiers = Field(default_factory=TrustTiers)

    @model_validator(mode="after")
    def _dynamic_requires_trace_source(self) -> "TaintConfig":
        if self.mode == "dynamic" and not self.trace_source:
            raise ValueError("detectors.taint.trace_source is required when mode is 'dynamic'")
        return self


class SandboxConfig(BaseModel):
    type: str = "docker"
    image: str
    network: str = "none"
    timeout_seconds: int = 120


class BehavioralConfig(BaseModel):
    enabled: bool = False
    sandbox: SandboxConfig | None = None
    probe_set: str | None = None
    baseline_run: str | None = None

    @model_validator(mode="after")
    def _enabled_requires_sandbox(self) -> "BehavioralConfig":
        if self.enabled and self.sandbox is None:
            raise ValueError("detectors.behavioral.sandbox is required when enabled is true")
        return self


class MLAnomalyConfig(BaseModel):
    enabled: bool = False
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    algorithm: Literal["isolation_forest", "lof", "one_class_svm"] = "isolation_forest"
    reference_corpus: str = "auto"
    min_reference_size: int = 20
    contamination: float = 0.05
    anomaly_score_threshold: float = 0.6
    show_nearest_neighbors: int = 3


class DetectorsConfig(BaseModel):
    heuristic: HeuristicConfig = Field(default_factory=HeuristicConfig)
    llm_judge: LLMJudgeConfig = Field(default_factory=LLMJudgeConfig)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    behavioral: BehavioralConfig = Field(default_factory=BehavioralConfig)
    ml_anomaly: MLAnomalyConfig = Field(default_factory=MLAnomalyConfig)

    def any_enabled(self) -> bool:
        return any(
            [
                self.heuristic.enabled,
                self.llm_judge.enabled,
                self.taint.enabled,
                self.behavioral.enabled,
                self.ml_anomaly.enabled,
            ]
        )


# ── Baseline / suppression ─────────────────────────────────────────

class BaselineConfig(BaseModel):
    file: str = "./.tool-scan-baseline.json"


class IgnoreMatch(BaseModel):
    source: str
    tool_name: str


class IgnoreRule(BaseModel):
    match: IgnoreMatch
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("ignore_rules[].reason must not be empty")
        return value


# ── Reporting ───────────────────────────────────────────────────────

class SarifReportConfig(BaseModel):
    output_path: str = "./tool-scan-results.sarif"


class JsonReportConfig(BaseModel):
    output_path: str = "./tool-scan-results.json"


class MarkdownReportConfig(BaseModel):
    output_path: str = "./tool-scan-report.md"


class ReportConfig(BaseModel):
    formats: list[Literal["terminal", "json", "sarif", "markdown"]] = Field(
        default_factory=lambda: ["terminal"]
    )
    sarif: SarifReportConfig = Field(default_factory=SarifReportConfig)
    json: JsonReportConfig = Field(default_factory=JsonReportConfig)
    markdown: MarkdownReportConfig = Field(default_factory=MarkdownReportConfig)
    fail_on_severity: Literal["low", "medium", "high", "critical"] = "high"
    min_severity_shown: Literal["low", "medium", "high", "critical"] = "low"


# ── Top level ───────────────────────────────────────────────────────

class ScanConfig(BaseModel):
    version: int = 1
    sources: list[SourceConfig]
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    ignore_rules: list[IgnoreRule] = Field(default_factory=list)
    report: ReportConfig = Field(default_factory=ReportConfig)

    @model_validator(mode="after")
    def _must_have_sources(self) -> "ScanConfig":
        if not self.sources:
            raise ValueError("config must declare at least one entry under sources[]")
        return self

    @model_validator(mode="after")
    def _must_have_enabled_detector(self) -> "ScanConfig":
        if not self.detectors.any_enabled():
            raise ValueError("config must have at least one detector enabled")
        return self

    @model_validator(mode="after")
    def _source_names_must_be_unique(self) -> "ScanConfig":
        names = [s.name for s in self.sources]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"source names must be unique, duplicated: {sorted(duplicates)}")
        return self


def load_config(path: str | Path) -> ScanConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    raw = yaml.safe_load(path.read_text())
    if raw is None:
        raise ConfigError(f"config file is empty: {path}")
    try:
        return ScanConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"invalid config at {path}: {exc}") from exc
