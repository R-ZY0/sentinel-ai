"""Typed local/Ollama adapters and explicit generic JSON REST preparation.

Network destinations must be exact server-allowlisted URLs, including paths.
Redirects, environment proxies, URL credentials and oversized replies are rejected.
"""
import json
import os
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener

from ..local_target import build_ollama_request, OLLAMA_BASE_URL, OLLAMA_MODEL


class TargetAdapterError(Exception):
    pass


def canonical_endpoint(value):
    url = urlsplit(str(value))
    if url.scheme not in {"http", "https"} or not url.hostname:
        raise ValueError("Expected an HTTP or HTTPS endpoint")
    if url.username or url.password or url.query or url.fragment:
        raise ValueError("Endpoint credentials, query strings and fragments are not supported")
    return urlunsplit((url.scheme.lower(), url.netloc.lower(), url.path.rstrip("/"), "", ""))


def allowed_endpoints():
    values = os.environ.get("TARGET_ALLOWED_ENDPOINTS", OLLAMA_BASE_URL).split(",")
    return {canonical_endpoint(value.strip()) for value in values if value.strip()}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class TargetReply:
    response: str
    status: str
    latency_ms: int


class TargetAdapter:
    def __init__(self, target):
        self.target = target
        self.endpoint = canonical_endpoint(target.endpoint)
        self.configuration = target.configuration or {}

    def respond(self, prompt):
        if self.endpoint not in allowed_endpoints():
            raise TargetAdapterError("Endpoint is not approved by the server")
        if not self.target.authorized:
            raise TargetAdapterError("Target testing authorization must be declared")
        if self.target.target_type in {"local", "ollama"}:
            body = build_ollama_request(prompt)
            body["model"] = self.configuration.get("model", OLLAMA_MODEL)
            url = self.endpoint + "/api/chat"
            field = "message.content"
        else:
            body = {self.configuration.get("prompt_field", "prompt"): prompt}
            body.update(self.configuration.get("static_body", {}))
            field = self.configuration.get("response_field", "response")
            url = self.endpoint
        return self._post(body, url, field)

    def respond_messages(self, messages):
        """Server-owned fixture messages for the configured local Ollama target."""
        require_scan_compatible(self.target)
        if self.endpoint not in allowed_endpoints():
            raise TargetAdapterError("Endpoint is not approved by the server")
        body = build_ollama_request("")
        body["messages"] = messages
        body["model"] = self.configuration.get("model", OLLAMA_MODEL)
        return self._post(body, self.endpoint + "/api/chat", "message.content")

    def _post(self, body, url, field):
        start = time.monotonic()
        request = Request(url, data=json.dumps(body).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            opener = build_opener(ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=self.configuration.get("timeout_seconds", 30)) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise TargetAdapterError("Target reply exceeded the size limit")
                data = json.loads(raw)
            value = data
            for part in field.split("."):
                value = value[part]
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Empty reply")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
            raise TargetAdapterError("Target did not return a usable JSON response") from None
        return TargetReply(value, "completed", round((time.monotonic() - start) * 1000))


def get_target_adapter(target):
    if target.target_type not in {"local", "ollama", "rest"}:
        raise TargetAdapterError("Unsupported target type")
    return TargetAdapter(target)


def require_scan_compatible(target):
    """Existing tool/fixture harness is intentionally limited to canonical Ollama.

Generic REST is prepared/validatable; calling external endpoints with privileged
fixture assumptions would falsely confirm evidence, so don't queue those scans.
"""
    if (target.target_type not in {"local", "ollama"}
            or canonical_endpoint(target.endpoint) != canonical_endpoint(OLLAMA_BASE_URL)
            or (target.configuration or {}).get("model", OLLAMA_MODEL) != OLLAMA_MODEL):
        raise TargetAdapterError("Scan execution currently requires the configured local Ollama target/model")
    if not target.authorized:
        raise TargetAdapterError("Target testing authorization must be declared")
