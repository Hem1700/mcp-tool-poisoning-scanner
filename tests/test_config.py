import pytest

from tool_scan.config import ConfigError, load_config


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return path


def test_loads_minimal_valid_config(tmp_path):
    path = _write(
        tmp_path,
        "config.yaml",
        """
version: 1
sources:
  - type: raw_json
    name: declared-schemas
    path: "./schemas/*.json"
""",
    )
    config = load_config(path)
    assert config.sources[0].name == "declared-schemas"
    assert config.detectors.heuristic.enabled is True
    assert config.detectors.llm_judge.enabled is False


def test_rejects_config_with_no_sources(tmp_path):
    path = _write(tmp_path, "config.yaml", "version: 1\nsources: []\n")
    with pytest.raises(ConfigError, match="at least one entry under sources"):
        load_config(path)


def test_rejects_config_with_no_detectors_enabled(tmp_path):
    path = _write(
        tmp_path,
        "config.yaml",
        """
version: 1
sources:
  - type: raw_json
    name: s
    path: "./schemas/*.json"
detectors:
  heuristic:
    enabled: false
  taint:
    enabled: false
""",
    )
    with pytest.raises(ConfigError, match="at least one detector enabled"):
        load_config(path)


def test_rejects_duplicate_source_names(tmp_path):
    path = _write(
        tmp_path,
        "config.yaml",
        """
version: 1
sources:
  - type: raw_json
    name: dup
    path: "./a/*.json"
  - type: raw_json
    name: dup
    path: "./b/*.json"
""",
    )
    with pytest.raises(ConfigError, match="duplicated"):
        load_config(path)


def test_rejects_ignore_rule_with_blank_reason(tmp_path):
    path = _write(
        tmp_path,
        "config.yaml",
        """
version: 1
sources:
  - type: raw_json
    name: s
    path: "./schemas/*.json"
ignore_rules:
  - match:
      source: s
      tool_name: debug_echo
    reason: ""
""",
    )
    with pytest.raises(ConfigError, match="reason must not be empty"):
        load_config(path)


def test_missing_config_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_dynamic_taint_mode_requires_trace_source(tmp_path):
    path = _write(
        tmp_path,
        "config.yaml",
        """
version: 1
sources:
  - type: raw_json
    name: s
    path: "./schemas/*.json"
detectors:
  taint:
    enabled: true
    mode: dynamic
""",
    )
    with pytest.raises(ConfigError, match="trace_source is required"):
        load_config(path)


def test_behavioral_enabled_requires_sandbox(tmp_path):
    path = _write(
        tmp_path,
        "config.yaml",
        """
version: 1
sources:
  - type: raw_json
    name: s
    path: "./schemas/*.json"
detectors:
  behavioral:
    enabled: true
""",
    )
    with pytest.raises(ConfigError, match="sandbox is required"):
        load_config(path)
