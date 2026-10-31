import base64
import os
from functools import lru_cache

from attack_engine.attack_run import AttackRun
from judge.baselines import BaselineConfig, BaselineRunner
from judge.canary_judge import CanaryRegexJudge

from .local_target import OLLAMA_BASE_URL


@lru_cache(maxsize=1)
def get_baseline_runner() -> BaselineRunner:
    return BaselineRunner(
        BaselineConfig(
            llm_host=OLLAMA_BASE_URL,
            llm_model=os.environ.get(
                "JUDGE_MODEL", "llama3.2:3b"
            ),
        )
    )


def review_attack(attack: AttackRun, *, canary: str) -> dict:
    if attack.status != "completed":
        raise ValueError("Only completed attacks can be reviewed")

    shared = get_baseline_runner()
    runner = BaselineRunner(
        canary_judge=CanaryRegexJudge([canary]),
        presidio_judge=shared.presidio_judge,
        llm_judge=shared.llm_judge,
        hybrid_judge=shared.hybrid_judge,
    )
    result = runner.evaluate(
        {
            "attack_id": attack.attack_id,
            "attack": attack.payload,
            "response": attack.actual_response,
            "expected_behavior": attack.expected_behavior,
        }
    )

    encoded = base64.b64encode(canary.encode()).decode()

    def redact(value):
        if isinstance(value, str):
            return value.replace(canary, "[REDACTED]").replace(
                encoded, "[REDACTED]"
            )
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return redact(result)