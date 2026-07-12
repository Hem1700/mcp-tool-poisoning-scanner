from tool_scan.config import LLMJudgeConfig
from tool_scan.detectors.llm_judge import JudgeVerdict, LLMJudgeDetector
from tool_scan.models import SourceType, ToolDefinition


class FakeJudgeClient:
    def __init__(self, verdicts: list[JudgeVerdict]) -> None:
        self._verdicts = iter(verdicts)
        self.prompts_seen: list[str] = []

    def judge(self, prompt: str) -> JudgeVerdict:
        self.prompts_seen.append(prompt)
        return next(self._verdicts)


def _tool(description: str) -> ToolDefinition:
    return ToolDefinition(
        name="get_weather", description=description, parameters={},
        source_type=SourceType.RAW_JSON, source_location="x.json", source_name="s",
    )


def test_flags_tool_when_verdict_is_suspicious_above_threshold():
    config = LLMJudgeConfig(enabled=True, confidence_threshold=0.6)
    client = FakeJudgeClient(
        [JudgeVerdict(suspicious=True, confidence=0.9, rationale="Instructs credential exfiltration")]
    )
    detector = LLMJudgeDetector(config, client=client)
    findings = detector.scan([_tool("some description")])
    assert len(findings) == 1
    assert findings[0].confidence == 0.9
    assert findings[0].severity.value == "high"


def test_does_not_flag_when_confidence_below_threshold():
    config = LLMJudgeConfig(enabled=True, confidence_threshold=0.8)
    client = FakeJudgeClient([JudgeVerdict(suspicious=True, confidence=0.5, rationale="maybe")])
    detector = LLMJudgeDetector(config, client=client)
    assert detector.scan([_tool("some description")]) == []


def test_does_not_flag_when_not_suspicious():
    config = LLMJudgeConfig(enabled=True)
    client = FakeJudgeClient([JudgeVerdict(suspicious=False, confidence=0.99, rationale="looks fine")])
    detector = LLMJudgeDetector(config, client=client)
    assert detector.scan([_tool("some description")]) == []


def test_respects_max_calls_per_scan_budget():
    config = LLMJudgeConfig(enabled=True, max_calls_per_scan=1)
    client = FakeJudgeClient([JudgeVerdict(suspicious=False, confidence=0.1, rationale="fine")] * 5)
    detector = LLMJudgeDetector(config, client=client)
    detector.scan([_tool(f"description {i}") for i in range(5)])
    assert len(client.prompts_seen) == 1


def test_prompt_includes_tool_description():
    config = LLMJudgeConfig(enabled=True)
    client = FakeJudgeClient([JudgeVerdict(suspicious=False, confidence=0.1, rationale="fine")])
    detector = LLMJudgeDetector(config, client=client)
    detector.scan([_tool("Fetches the weather for a city.")])
    assert "Fetches the weather for a city." in client.prompts_seen[0]


def test_does_not_construct_real_client_when_tools_list_is_empty(monkeypatch):
    from tool_scan.detectors import llm_judge

    def _raise_if_constructed(*args, **kwargs):
        raise AssertionError(
            "AnthropicJudgeClient should not be constructed for an empty tool list"
        )

    monkeypatch.setattr(llm_judge, "AnthropicJudgeClient", _raise_if_constructed)

    config = LLMJudgeConfig(enabled=True)
    detector = LLMJudgeDetector(config)  # no client injected: must not construct AnthropicJudgeClient here
    assert detector.scan([]) == []
