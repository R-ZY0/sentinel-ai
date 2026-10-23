"""Authorized local PyRIT -> Ollama integration entrypoint."""

import asyncio
import sys

from pyrit.setup import IN_MEMORY, initialize_pyrit_async

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_case_adapter import attack_case_to_attack_run
from attack_engine.ollama_local_pyrit_target import OllamaLocalPyRITTarget
from app.local_target import OLLAMA_BASE_URL, OLLAMA_MODEL, LOCAL_TARGET_MODE
from attack_engine.pyrit_runner import PyRITRunner


async def run_local_pyrit():
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    target = OllamaLocalPyRITTarget()

    runner = PyRITRunner(target=target, timeout_seconds=90)

    attack = attack_case_to_attack_run(
        ATTACK_LIBRARY[0],
        "local-ollama",
    )

    return await runner.run(attack)


def main():
    result = asyncio.run(run_local_pyrit())

    print("Target mode:", LOCAL_TARGET_MODE)
    print("Ollama base URL:", OLLAMA_BASE_URL)
    print("Ollama model:", OLLAMA_MODEL)
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
