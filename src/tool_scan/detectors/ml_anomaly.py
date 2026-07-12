from __future__ import annotations

from typing import Protocol

from tool_scan.config import MLAnomalyConfig
from tool_scan.detectors.base import Detector
from tool_scan.findings import Finding, Severity
from tool_scan.models import ToolDefinition


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._model.encode(texts).tolist()


def _build_scorer(algorithm: str, contamination: float):
    if algorithm == "isolation_forest":
        from sklearn.ensemble import IsolationForest

        return IsolationForest(contamination=contamination, random_state=0)
    if algorithm == "lof":
        from sklearn.neighbors import LocalOutlierFactor

        return LocalOutlierFactor(contamination=contamination, novelty=True)
    if algorithm == "one_class_svm":
        from sklearn.svm import OneClassSVM

        return OneClassSVM(nu=contamination)
    raise ValueError(f"unknown ml_anomaly algorithm: {algorithm}")


def _cosine_distance(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 1.0
    return 1.0 - (dot / (norm_a * norm_b))


class MLAnomalyDetector(Detector):
    name = "ml_anomaly"

    def __init__(self, config: MLAnomalyConfig, embedder: Embedder | None = None) -> None:
        self.config = config
        self._embedder = embedder or SentenceTransformerEmbedder(config.embedding_model)

    def scan(self, tools: list[ToolDefinition]) -> list[Finding]:
        if len(tools) < self.config.min_reference_size:
            return []

        descriptions = [t.description for t in tools]
        embeddings = self._embedder.embed(descriptions)

        scorer = _build_scorer(self.config.algorithm, self.config.contamination)
        scorer.fit(embeddings)
        if hasattr(scorer, "score_samples"):
            raw_scores = scorer.score_samples(embeddings)
        else:
            raw_scores = scorer.decision_function(embeddings)

        min_score, max_score = min(raw_scores), max(raw_scores)
        span = (max_score - min_score) or 1.0
        normalized = [(max_score - s) / span for s in raw_scores]  # higher = more anomalous

        findings: list[Finding] = []
        for i, tool in enumerate(tools):
            if normalized[i] < self.config.anomaly_score_threshold:
                continue
            distances = sorted(
                ((j, _cosine_distance(embeddings[i], embeddings[j])) for j in range(len(tools)) if j != i),
                key=lambda pair: pair[1],
            )
            neighbor_names = [tools[j].name for j, _ in distances[: self.config.show_nearest_neighbors]]
            findings.append(
                Finding(
                    tool_id=tool.id,
                    tool_name=tool.name,
                    source_name=tool.source_name,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    summary=(
                        f"Description is a statistical outlier (score {normalized[i]:.2f}) "
                        f"relative to {len(tools) - 1} other tool description(s) in this scan"
                    ),
                    evidence=(
                        f"nearest benign comparisons: {', '.join(neighbor_names)}"
                        if neighbor_names
                        else "no comparison tools available"
                    ),
                    confidence=round(normalized[i], 4),
                )
            )
        return findings
