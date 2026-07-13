import pytest

from tool_scan.config import TaintConfig, TrustTiers
from tool_scan.detectors.taint import TaintGraphDetector
from tool_scan.models import SourceType, ToolDefinition


def _tool(name: str, source_name: str = "s") -> ToolDefinition:
    return ToolDefinition(
        name=name, description="d", parameters={},
        source_type=SourceType.RAW_JSON, source_location="x.json", source_name=source_name,
    )


def test_flags_edge_between_low_trust_and_high_trust_tool_in_same_source():
    config = TaintConfig(
        enabled=True, trust_tiers=TrustTiers(low_trust=["search_web"], high_trust=["send_email"])
    )
    detector = TaintGraphDetector(config)
    findings = detector.scan([_tool("search_web"), _tool("send_email")])
    assert len(findings) == 1
    assert "search_web" in findings[0].evidence
    assert "send_email" in findings[0].evidence


def test_does_not_flag_across_different_sources():
    config = TaintConfig(
        enabled=True, trust_tiers=TrustTiers(low_trust=["search_web"], high_trust=["send_email"])
    )
    detector = TaintGraphDetector(config)
    findings = detector.scan(
        [_tool("search_web", source_name="a"), _tool("send_email", source_name="b")]
    )
    assert findings == []


def test_no_findings_when_only_low_trust_tools_present():
    config = TaintConfig(
        enabled=True, trust_tiers=TrustTiers(low_trust=["search_web"], high_trust=["send_email"])
    )
    detector = TaintGraphDetector(config)
    assert detector.scan([_tool("search_web")]) == []


def test_dynamic_mode_raises_not_implemented():
    config = TaintConfig(enabled=True, mode="dynamic", trace_source="./traces.json")
    with pytest.raises(NotImplementedError):
        TaintGraphDetector(config)
