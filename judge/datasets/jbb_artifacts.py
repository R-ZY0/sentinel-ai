import json
from pathlib import Path


def load_jbb_artifacts(file_path):
    path = Path(file_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")

    jailbreaks = data.get("jailbreaks")

    if not isinstance(jailbreaks, list):
        raise ValueError("Missing or invalid jailbreaks list")

    cases = []
    skipped = 0

    for position, item in enumerate(jailbreaks):
        if not isinstance(item, dict):
            skipped += 1
            continue

        prompt = item.get("prompt")
        response = item.get("response")

        if (
            not isinstance(prompt, str)
            or not prompt.strip()
            or not isinstance(response, str)
            or not response.strip()
        ):
            skipped += 1
            continue

        cases.append({
            "case_id": f"{path.stem}-{item.get('index', position)}",
            "source": "JailbreakBench/artifacts",
            "attack_type": "jailbreak",
            "category": item.get("category"),
            "attack": prompt,
            "response": response,
            "jailbreak_label": item.get("jailbroken"),
            "leakage_ground_truth": None,
            "model": path.stem,
        })

    stats = {
        "total": len(jailbreaks),
        "usable": len(cases),
        "skipped": skipped,
    }

    return cases, stats