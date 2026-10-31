"""Offline static CTI context and conservative CVSS v4.0 readiness checks.

This component adds *reference context* only. It does not consume a CTI feed,
identify an active campaign, compute a CVSS vector, or modify the Finding schema.
The trusted canonical taxonomy files remain owned by the security workstream.
"""
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from .finding import ROOT


def _source_context(path: Path, case_id: str, field: str) -> tuple[list[dict], list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    mapping = [m for m in data["mappings"] if m["test_case_id"] == case_id]
    if len(mapping) != 1:
        raise ValueError(f"Expected one canonical {field} mapping for {case_id}")
    entry = mapping[0]
    raw = entry[field]
    items = [raw] if isinstance(raw, dict) else raw
    if not isinstance(items, list) or not items:
        raise ValueError("Missing canonical taxonomy mapping")
    expected = [{k: v[k] for k in ("id", "name", "role") if k in v} for v in items]
    urls = entry.get("source_urls")
    if urls is None:
        urls = [entry["source_url"]]
    if not isinstance(urls, list) or not all(
        isinstance(u, str) and u.startswith("https://") for u in urls
    ):
        raise ValueError("Invalid local reference source")
    return expected, list(dict.fromkeys(urls))


def triage_finding(finding: dict, *, root: Path = ROOT) -> dict:
    """Annotate schema-valid findings with non-authoritative local references.

    No score or severity rating is assigned here; only a reviewed, defensible
    CVSS v4.0 assessment can fill these fields in the shared Finding contract.
    """
    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary")
    root = Path(root)
    schema = json.loads((root / "security/finding_schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(finding)
    case_id = finding["test_case_id"]
    classification = finding["classification"]
    owasp, owasp_urls = _source_context(
        root / "security/mappings/owasp_mapping.json", case_id, "owasp"
    )
    cwe, cwe_urls = _source_context(
        root / "security/mappings/cwe_mapping.json", case_id, "cwe"
    )
    if classification["owasp"] != owasp or classification["cwe"] != cwe:
        raise ValueError("Finding classification differs from canonical mapping")
    status = finding["status"]
    severity = finding["severity"]
    if status == "confirmed" and not any(
        e["validated"] and e["type"] == "leakage" for e in finding["evidence"]
    ):
        raise ValueError("Confirmed finding lacks validated disclosure evidence")
    if severity.get("assessment_status", "pending") != "pending" or any(
        severity.get(k) is not None for k in ("score", "vector", "rating")
    ):
        raise ValueError("Triage expects an unassessed Finding; do not auto-score")
    if status == "confirmed":
        disposition = "requires_impact_and_cvss_review"
        next_actions = [
            "Verify authorization, trust boundaries and provenance against target records",
            "Assess impact and CVSS v4.0 Base metrics with a trained reviewer",
            "Validate response evidence and approve final disposition",
        ]
    elif status == "potential":
        disposition = "requires_evidence_review"
        next_actions = [
            "Resolve missing or ambiguous independently verified response evidence",
            "Verify target access, fixture provenance and authorization",
        ]
    else:
        disposition = "no_confirmed_disclosure"
        next_actions = ["Retain the bounded no-match observation without scoring a vulnerability"]
    return {
        "finding_id": finding["finding_id"],
        "test_case_id": case_id,
        "finding_status": status,
        "disposition": disposition,
        "severity_readiness": {
            "cvss_version": "4.0",
            "assessment_status": "pending",
            "score": None,
            "rating": None,
            "vector": None,
            "review_required": status == "confirmed",
            "next_actions": next_actions,
        },
        "cti_context": {
            "context_type": "static_taxonomy_references",
            "owasp": owasp,
            "cwe": cwe,
            "source_urls": list(dict.fromkeys(owasp_urls + cwe_urls)),
            "external_feed_connected": False,
            "threat_actor_attributed": False,
            "campaign_attributed": False,
            "indicator_observations": [],
        },
    }
