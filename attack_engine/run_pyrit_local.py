"""Authorized local PyRIT -> Ollama integration entrypoint."""

import asyncio
import os
import sys

from pyrit.setup import IN_MEMORY, initialize_pyrit_async

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_case_adapter import attack_case_to_attack_run
from attack_engine.ollama_target import OllamaTarget
from attack_engine.ollama_local_pyrit_target import OllamaLocalPyRITTarget
from attack_engine.pyrit_runner import PyRITRunner


class LocalOllamaBridge:
    """Adapt the working OllamaTarget.send() API to respond()."""

    def __init__(
        self,
        model="llama3.2:3b",
        url="http://127.0.0.1:11434/api/generate",
    ):
        self.target = OllamaTarget(model=model, url=url)

    def respond(self, prompt: str) -> str:
        return self.target.send(prompt)


async def run_local_pyrit():
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    target = OllamaLocalPyRITTarget()
    target.local_target = LocalOllamaBridge(
        model=os.environ.get("SENTINEL_OLLAMA_MODEL", "llama3.2:3b"),
        url=os.environ.get(
            "SENTINEL_OLLAMA_URL",
            "http://127.0.0.1:11434/api/generate",
        ),
    )

    runner = PyRITRunner(target=target, timeout_seconds=90)

    attack = attack_case_to_attack_run(
        ATTACK_LIBRARY[0],
        "local-ollama",
    )

    return await runner.run(attack)


def main():
    result = asyncio.run(run_local_pyrit())

    print("Attack ID:", result.attack_id)
    print("Category:", result.category)
    print("Status:", result.status)
    print("Response:", repr((result.actual_response or "")[:200]))
    print("Evaluation:", result.evaluation_status)
    print("Error:", result.execution_error)

    if (
        result.attack_id == ATTACK_LIBRARY[0].attack_id
        and result.status == "completed"
        and result.actual_response
        and result.execution_error is None
    ):
        print("PYRIT LOCAL INTEGRATION: PASS")
        return 0

    print("PYRIT LOCAL INTEGRATION: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
