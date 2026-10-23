import asyncio

from pyrit.memory import CentralMemory, SQLiteMemory

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_case_adapter import attack_case_to_attack_run
from attack_engine.ollama_pyrit_target import create_ollama_pyrit_target
from attack_engine.pyrit_runner import PyRITRunner


async def main():
    memory = SQLiteMemory(db_path=":memory:", silent=True)
    CentralMemory.set_memory_instance(memory)

    target = create_ollama_pyrit_target()
    runner = PyRITRunner(target)

    attack = attack_case_to_attack_run(
        ATTACK_LIBRARY[0],
        "Local Llama 3.2",
    )

    result = await runner.run(attack)

    print(result)


asyncio.run(main())
