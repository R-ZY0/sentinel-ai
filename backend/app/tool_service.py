"""Internal, isolated scanner process host. No published host port or DB access."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    canary: SecretStr = Field(min_length=32, max_length=128)


@app.get("/health")
def health():
    from importlib.metadata import version

    tool = os.environ["SENTINEL_TOOL"]
    return {"tool": tool, "version": version(tool)}


@app.post("/execute")
def execute(payload: ToolRequest):
    tool = os.environ["SENTINEL_TOOL"]
    if tool not in {"garak", "pyrit"}:
        raise HTTPException(503, "Unsupported tool configuration")
    # A new process isolates PyRIT memory, fixture values and scanner state.
    with tempfile.TemporaryDirectory(prefix="sentinel_tool_") as directory:
        output = Path(directory) / "result.json"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "app.tool_process", tool, str(output)],
                input=json.dumps({"canary": payload.canary.get_secret_value()}),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "Scanner execution timed out") from None
        # Scanner console output may contain private prompts; never return it.
        if result.returncode != 0 or not output.is_file():
            error_type = "ScannerProcessError"
            if output.is_file():
                error_type = json.loads(output.read_text(encoding="utf-8")).get(
                    "error_type", error_type
                )
            raise HTTPException(502, {
                "message": "Scanner execution failed; no usable result",
                "error_type": error_type,
            })
        return json.loads(output.read_text(encoding="utf-8"))
