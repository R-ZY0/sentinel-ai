"""Live release gate, run explicitly inside the API container (not unit discovery).

Creates a separate temporary-credential account and leaves labeled scan history
for audit. Never prints credentials, tokens, raw target responses or fixture values.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, ProxyHandler, build_opener

ATTACKS = ["SPL-001", "DL-001", "RL-001", "DL-003", "PI-002", "PYRIT-PI-001", "GARAK-DAN-001"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="/tmp/week34-live-results.json")
    parser.add_argument("--require-finding", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800)
    options = parser.parse_args()
    opener = build_opener(ProxyHandler({}))
    token = None

    def request(method, path, payload=None, *, form=False, expected=200):
        body = urlencode(payload).encode() if form else json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = Request("http://127.0.0.1:8000" + path, data=body, headers=headers, method=method)
        try:
            with opener.open(req, timeout=180) as response:
                status, result = response.status, json.load(response)
        except HTTPError as exc:
            status = exc.code
            result = {}  # Do not log a server body that could reflect credentials.
        if status != expected:
            raise RuntimeError(f"{method} {path}: expected HTTP {expected}, received {status}")
        return result

    request("GET", "/health")
    identity = "week34-acceptance-" + secrets.token_hex(8) + "@example.com"
    password = secrets.token_urlsafe(32)
    request("POST", "/auth/register", {"email": identity, "password": password}, expected=201)
    login = request("POST", "/auth/login", {"username": identity, "password": password}, form=True)
    token = login["access_token"]
    target = request("POST", "/targets", {
        "name": "Week 3-4 automated live acceptance", "endpoint": "http://ollama:11434/",
        "target_type": "ollama", "authorized": True,
        "configuration": {"model": "qwen2.5:0.5b", "timeout_seconds": 120},
    }, expected=201)
    validation = request("POST", f"/targets/{target['id']}/validate")
    if validation["status"] != "valid":
        raise RuntimeError("Target connectivity validation failed")
    scan = request("POST", "/scans", {"target_id": target["id"], "configuration": {
        "pipeline": "week34", "engines": ["library", "pyrit", "garak"], "attack_ids": ATTACKS,
    }, "auto_start": False}, expected=201)
    request("POST", f"/scans/{scan['id']}/start", expected=202)
    print(f"Live scan started: {scan['id']}", flush=True)
    deadline = time.monotonic() + options.timeout
    last = None
    while time.monotonic() < deadline:
        scan = request("GET", f"/scans/{scan['id']}")
        if scan["status"] != last:
            print("Scan status:", scan["status"], flush=True)
            last = scan["status"]
        if scan["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(5)
    if scan["status"] != "completed":
        raise RuntimeError("Live scan did not complete successfully: " + scan["status"])
    results = request("GET", f"/scans/{scan['id']}/results")["results"]
    if not set(ATTACKS).issubset({row["catalog_attack_id"] for row in results}):
        raise RuntimeError("A selected attack has no stored result")
    if {f"TC-{number:03}" for number in range(1, 6)} != {row["test_case_id"] for row in results}:
        raise RuntimeError("Not all five security scenarios were stored")
    findings = 0
    for row in results:
        if row["status"] != "completed" or not row["target_response"] or row["receipt_integrity"] != "verified":
            raise RuntimeError("Missing completed response or verified receipt")
        comparison = row["comparison"]
        if set(comparison["baselines"]) != {"B0", "B1"} or "llm_judge" not in comparison:
            raise RuntimeError("Baseline versus LLM comparison is missing")
        if comparison["llm_judge"]["signals"].get("evaluation_error"):
            raise RuntimeError("LLM Judge returned an evaluation error")
        runtime = comparison["runtime"]
        if not {runtime["target_model"], runtime["judge_model"]}.issubset(runtime["model_digests"]):
            raise RuntimeError("Target/judge model version digests were not recorded")
        if row["execution"]["engine"] in {"pyrit", "garak"} and not row["execution"].get("tool_version"):
            raise RuntimeError("Tool version was not recorded")
        document = row["security"]["finding"]
        if document["status"] == "confirmed":
            persisted = next((item for item in row["persisted_findings"] if item["id"] == document["finding_id"]), None)
            if (not persisted or persisted["status"] != "confirmed"
                    or persisted["category"] != document["category"] or not persisted["evidence_count"]
                    or set(persisted["mapping_taxonomies"]) != {"owasp", "cwe"}):
                raise RuntimeError("Confirmed finding lacks matching persisted evidence/mapping rows")
            findings += 1
        elif row["persisted_findings"]:
            raise RuntimeError("Non-confirmed validation unexpectedly created a finding row")
        print(row["catalog_attack_id"], row["test_case_id"],
              "judge=" + comparison["llm_judge"]["verdict"],
              "security=" + row["security"]["validation"]["verdict"], "receipt=verified", flush=True)
    if options.require_finding and not findings:
        raise RuntimeError("No confirmed finding was stored in the requested positive demo")
    cancelled = request("POST", "/scans", {"target_id": target["id"], "configuration": {
        "pipeline": "week34", "engines": ["library"], "attack_ids": ["SPL-001"]}}, expected=201)
    cancelled = request("POST", f"/scans/{cancelled['id']}/cancel")
    request("POST", f"/scans/{cancelled['id']}/start", expected=409)
    if cancelled["status"] != "cancelled" or cancelled["started_at"] is not None:
        raise RuntimeError("Cancel-before-start did not preserve cancelled state")
    report = {"recorded_at": datetime.now(timezone.utc).isoformat(), "gate": "PASS",
        "scope": "controlled local authorized synthetic fixtures; not production RAG assurance",
        "target_id": target["id"], "scan": scan, "validation": validation,
        "cancelled_scan_id": cancelled["id"], "confirmed_findings": findings, "results": results}
    Path(options.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"WEEK 3-4 LIVE ACCEPTANCE: PASS ({len(results)} results, {findings} confirmed findings)", flush=True)
    print("Redacted evidence report:", options.output, flush=True)


if __name__ == "__main__":
    main()
