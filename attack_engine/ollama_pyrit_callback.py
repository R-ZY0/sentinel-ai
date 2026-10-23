import json


def ollama_response_callback(response):
    data = json.loads(response.content)
    return data["response"]
