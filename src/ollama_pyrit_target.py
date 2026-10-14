from pyrit.prompt_target import HTTPTarget

from src.ollama_pyrit_callback import ollama_response_callback


def create_ollama_pyrit_target():
    http_request = """POST http://localhost:11434/api/generate HTTP/1.1
Content-Type: application/json

{"model":"llama3.2:3b","prompt":"{PROMPT}","stream":false}"""

    return HTTPTarget(
        http_request=http_request,
        prompt_regex_string="{PROMPT}",
        use_tls=False,
        callback_function=ollama_response_callback,
        model_name="llama3.2:3b",
        timeout=120.0,
    )
