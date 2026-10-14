

import asyncio
import os

from pyrit.memory import CentralMemory, SQLiteMemory

from src.ollama_pyrit_target import create_ollama_pyrit_target
from src.pyrit_runner import PyRITRunner
from src.attack_library_runner import run_attack_library
from src.finding_repository import FindingRepository


async def main():
    memory = SQLiteMemory(db_path=":memory:", silent=True)
    CentralMemory.set_memory_instance(memory)

    target = create_ollama_pyrit_target()
    runner = PyRITRunner(target)
    repository = FindingRepository(host="127.0.0.1")

    results = await run_attack_library(
        runner,
        "Local Llama 3.2",
        finding_repository=repository,
    )

    for result in results:
        print("=" * 60)
        print("ID:", result.attack_id)
        print("Category:", result.category)
        print("Execution Status:", result.status)
        print("Evaluation Status:", result.evaluation_status)
        print("Passed:", result.passed)
        print("Judge Reason:", result.judge_reason)

    print("=" * 60)
    print("Total attacks:", len(results))
    print(
        "Potential findings:",
        sum(1 for result in results if result.evaluation_status == "fail"),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        os.environ.pop("POSTGRES_PASSWORD", None)
