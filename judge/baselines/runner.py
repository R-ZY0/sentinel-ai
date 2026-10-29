"""Compare B0-B3 on one response; never creates a confirmed Finding."""
from collections.abc import Mapping
from typing import Any

from judge.adapters import normalize_target_response
from judge.baselines.config import BaselineConfig
from judge.verdict import JudgeVerdict


class BaselineRunner:
    def __init__(self, config: BaselineConfig | None = None, *,
                 canary_judge=None, presidio_judge=None, llm_judge=None,
                 hybrid_judge=None) -> None:
        config = config or BaselineConfig()
        if canary_judge is None:
            from judge.canary_judge import CanaryRegexJudge
            canary_judge = CanaryRegexJudge(config.canaries, config.regex_patterns)
        if presidio_judge is None:
            from judge.presidio_judge import PresidioJudge
            presidio_judge = PresidioJudge(score_threshold=config.presidio_score_threshold)
        if llm_judge is None:
            from judge.llm_judge import LLMJudge
            llm_judge = LLMJudge(model=config.llm_model, host=config.llm_host)
        if hybrid_judge is None:
            from judge.hybrid_judge import HybridJudge
            hybrid_judge = HybridJudge(presidio_judge=presidio_judge, llm_judge=llm_judge)
        self.canary_judge = canary_judge
        self.presidio_judge = presidio_judge
        self.llm_judge = llm_judge
        self.hybrid_judge = hybrid_judge

    def evaluate(self, target_response: Mapping[str, Any], *,
                 attack: str | None = None,
                 expected_behavior: str | None = None) -> dict[str, Any]:
        record = normalize_target_response(target_response, attack=attack,
                                           expected_behavior=expected_behavior)
        results: dict[str, JudgeVerdict] = {
            "B0": self.canary_judge.judge(record.response),
            "B1": self.presidio_judge.judge(record.response),
            "B2": self.llm_judge.judge(record.attack, record.response,
                                       record.expected_behavior),
            "B3": self.hybrid_judge.judge(record.attack, record.response,
                                          record.expected_behavior),
        }
        if not all(isinstance(result, JudgeVerdict) for result in results.values()):
            raise TypeError("each baseline must return JudgeVerdict")
        return {
            "attack_id": record.attack_id,
            "advisory_only": True,
            "baselines": {name: verdict.to_dict() for name, verdict in results.items()},
        }
