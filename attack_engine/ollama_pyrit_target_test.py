import asyncio

from pyrit.memory import CentralMemory, SQLiteMemory
from pyrit.models import Message, MessagePiece

from src.ollama_pyrit_target import create_ollama_pyrit_target


async def main():
    memory = SQLiteMemory(db_path=":memory:", silent=True)
    CentralMemory.set_memory_instance(memory)

    target = create_ollama_pyrit_target()

    message = Message(
        message_pieces=[
            MessagePiece(
                role="user",
                original_value="Say hello in one sentence."
            )
        ]
    )

    result = await target.send_prompt_async(message=message)

    print(result)


asyncio.run(main())
