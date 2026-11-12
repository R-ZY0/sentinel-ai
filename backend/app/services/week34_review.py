"""Compare advisory baselines with the team's Week 3 local LLM Judge."""
import os
from functools import lru_cache
from importlib.metadata import version, PackageNotFoundError
from urllib.request import build_opener, ProxyHandler
import json
import hashlib
from pathlib import Path
from judge.datasets.leakage_labels import load_leakage_dataset
from judge.datasets import leakage_labels

from judge.canary_judge import CanaryRegexJudge
from judge.week3_llm_judge import Week3LLMJudge
from ..local_target import OLLAMA_BASE_URL, OLLAMA_MODEL
from .week34_scenarios import redact


@lru_cache(maxsize=1)
def judges():
    from judge.presidio_judge import PresidioJudge
    from ollama import Client
    return (PresidioJudge(), Week3LLMJudge(
        model=os.environ.get("JUDGE_MODEL", "llama3.2:3b"), host=OLLAMA_BASE_URL,
        client=Client(host=OLLAMA_BASE_URL, timeout=120), seed=42))


@lru_cache(maxsize=1)
def runtime_metadata():
    packages = {}
    for name in ("ollama", "presidio-analyzer", "pydantic", "sqlalchemy", "celery"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = "unavailable"
    model = os.environ.get("JUDGE_MODEL", "llama3.2:3b")
    metadata = {"packages": packages, "target_model": OLLAMA_MODEL,
                "judge_model": model, "temperature": 0, "seed": 42,
                "judge_type": "week3_llm", "model_digests": {}}
    try:
        with build_opener(ProxyHandler({})).open(OLLAMA_BASE_URL + "/api/tags", timeout=5) as response:
            tags = json.load(response)["models"]
        metadata["model_digests"] = {item["name"]: item["digest"] for item in tags
            if item["name"] in {model, OLLAMA_MODEL}}
    except Exception:
        metadata["model_metadata_status"] = "unavailable"
    return metadata


@lru_cache(maxsize=1)
def dataset_metadata():
    path = Path(leakage_labels.__file__).with_name("tc_week34_synthetic.json")
    cases = load_leakage_dataset(path)
    return {"source": "judge/datasets/tc_week34_synthetic.json",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "case_ids": [case["test_case_id"] for case in cases],
        "labels": ["LEAK", "NO_LEAK", "AMBIGUOUS"],
        "live_ground_truth": "unassigned; dataset labels do not establish a live response label"}


def review(attack, fixture):
    if attack.status != "completed":
        raise ValueError("Cannot judge an unsuccessful execution")
    references = fixture["values"]
    pii, llm = judges()
    baselines = {
        "B0": CanaryRegexJudge([item["value"] for item in references]).judge(attack.actual_response).to_dict(),
        "B1": pii.judge(attack.actual_response).to_dict(),
    }
    result = llm.judge(attack.payload, attack.actual_response, attack.expected_behavior,
        trusted_references={item["id"]: item["value"] for item in references}).to_dict()
    return redact({"attack_id": attack.attack_id, "advisory_only": True,
        "baselines": baselines, "llm_judge": result, "runtime": runtime_metadata(),
        "dataset": dataset_metadata()}, references)
