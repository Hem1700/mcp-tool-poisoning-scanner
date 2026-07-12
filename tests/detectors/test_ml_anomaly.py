from tool_scan.config import MLAnomalyConfig
from tool_scan.detectors.ml_anomaly import MLAnomalyDetector
from tool_scan.models import SourceType, ToolDefinition


class FakeEmbedder:
    def __init__(self, vectors: dict[str, list[float]]) -> None:
        self._vectors = vectors

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vectors[t] for t in texts]


def _tool(name: str, description: str) -> ToolDefinition:
    return ToolDefinition(
        name=name, description=description, parameters={},
        source_type=SourceType.RAW_JSON, source_location="x.json", source_name="s",
    )


def test_flags_the_outlier_tool_among_a_normal_cluster():
    normal_vectors = {f"normal tool {i}": [0.0 + i * 0.01, 0.0 + i * 0.01] for i in range(20)}
    outlier_description = "wildly different topic entirely"
    vectors = {**normal_vectors, outlier_description: [50.0, 50.0]}

    tools = [_tool(f"tool_{i}", desc) for i, desc in enumerate(normal_vectors)]
    tools.append(_tool("outlier_tool", outlier_description))

    embedder = FakeEmbedder(vectors)
    config = MLAnomalyConfig(enabled=True, min_reference_size=5, anomaly_score_threshold=0.5)
    detector = MLAnomalyDetector(config, embedder=embedder)

    findings = detector.scan(tools)
    assert "outlier_tool" in {f.tool_name for f in findings}


def test_skips_scoring_below_min_reference_size():
    embedder = FakeEmbedder({"a": [0.0, 0.0], "b": [1.0, 1.0]})
    config = MLAnomalyConfig(enabled=True, min_reference_size=20)
    detector = MLAnomalyDetector(config, embedder=embedder)
    assert detector.scan([_tool("a", "a"), _tool("b", "b")]) == []


def test_finding_includes_nearest_neighbor_evidence():
    normal_vectors = {f"normal {i}": [float(i), float(i)] for i in range(10)}
    outlier_description = "totally unrelated"
    vectors = {**normal_vectors, outlier_description: [500.0, 500.0]}
    tools = [_tool(f"tool_{i}", desc) for i, desc in enumerate(normal_vectors)]
    tools.append(_tool("outlier_tool", outlier_description))

    embedder = FakeEmbedder(vectors)
    config = MLAnomalyConfig(
        enabled=True, min_reference_size=5, anomaly_score_threshold=0.5, show_nearest_neighbors=2
    )
    detector = MLAnomalyDetector(config, embedder=embedder)
    findings = detector.scan(tools)
    outlier_finding = next(f for f in findings if f.tool_name == "outlier_tool")
    assert "nearest benign comparisons" in outlier_finding.evidence
