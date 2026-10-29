"""Build Ollama requests from Garak conversations without losing roles.

This is a request adapter only, not yet a registered Garak generator.
"""

def _turns(conversation):
    turns = getattr(conversation, "turns", None)
    if not turns:
        raise ValueError("Conversation must contain turns")

    messages = []
    for turn in turns:
        role = str(turn.role).lower()
        if role not in ("system", "user", "assistant"):
            raise ValueError(f"Unsupported role: {role}")

        content = getattr(turn.content, "text", None)
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Turn must contain nonempty text")

        messages.append({"role": role, "content": content})

    return messages


def build_conversation_request(
    conversation,
    *,
    model,
    mode,
    protected_system_prompt=None,
):
    """Return a local Ollama chat request.

    protected: use only the trusted target's system prompt.
    synthetic: preserve the probe's system/user conversation.
    """
    if not isinstance(model, str) or not model.strip():
        raise ValueError("Model is required")

    messages = _turns(conversation)

    if mode == "protected":
        if not isinstance(protected_system_prompt, str) or not protected_system_prompt.strip():
            raise ValueError("Trusted protected system prompt is required")
        if messages[0]["role"] == "system":
            raise ValueError(
                "Protected mode must not silently replace a probe system turn"
            )
        messages = [
            {"role": "system", "content": protected_system_prompt},
            *messages,
        ]
    elif mode == "synthetic":
        if protected_system_prompt is not None:
            raise ValueError("Protected prompt cannot be combined with synthetic mode")
        if len(messages) < 2:
            raise ValueError("Synthetic mode requires system and user turns")
        if messages[0]["role"] != "system" or messages[1]["role"] != "user":
            raise ValueError("Synthetic mode requires system then user")
    else:
        raise ValueError("Unsupported mode")

    return {
        "model": model,
        "stream": False,
        "messages": messages,
        "options": {
            "temperature": 0,
            "seed": 42,
            "num_predict": 256,
        },
    }
