

from pyrit.prompt_target import PromptTarget
from pyrit.models.messages.message import Message
from pyrit.models.messages.conversations import construct_response_from_request

from app.local_target import LocalTarget


class OllamaLocalPyRITTarget(PromptTarget):
    def __init__(self):
        super().__init__(
            endpoint="local-ollama",
            model_name="configured-local-model",
        )
        self.local_target = LocalTarget()

    async def _send_prompt_to_target_async(
        self,
        *,
        normalized_conversation: list[Message],
    ) -> list[Message]:
        if not normalized_conversation:
            raise ValueError("PyRIT provided an empty conversation.")

        request_message = normalized_conversation[-1]
        request_piece = request_message.get_piece()

        prompt = request_piece.converted_value or request_piece.original_value
        response_text = self.local_target.respond(prompt)

        response_message = construct_response_from_request(
            request=request_piece,
            response_text_pieces=[response_text],
        )

        return [response_message]
