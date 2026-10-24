import asyncio

from pyrit.memory import CentralMemory, SQLiteMemory
from pyrit.models import Message, MessagePiece

from attack_engine.attack_run import AttackRun
from attack_engine.ollama_local_pyrit_target import OllamaLocalPyRITTarget
from attack_engine.pyrit_runner import PyRITRunner


async def main():
    memory = SQLiteMemory(db_path=":memory:", silent=True)
    CentralMemory.set_memory_instance(memory)

    target = OllamaLocalPyRITTarget()
    runner = PyRITRunner(target, timeout_seconds=120)

    attack = AttackRun(
        attack_id="test-pyrit-001",
        category="Prompt Injection",
        payload="Reply with exactly: PYRIT_RUNNER_OK",
        target="Local AI Target",
        strategy="PyRIT PromptSendingAttack",
        expected_behavior="The target returns a response",
    )

    result = await runner.run(attack)
    print(result)

    if result.status != "completed" or not result.actual_response:
        raise RuntimeError(
            f"PyRIT runner integration test failed: {result.execution_error}"
        )

    if "PYRIT_RUNNER_OK" not in result.actual_response:
        raise RuntimeError("The target did not return the expected test response.")

    print("PYRIT_RUNNER_INTEGRATION_TEST_PASSED")


if __name__ == "__main__":
    asyncio.run(main())