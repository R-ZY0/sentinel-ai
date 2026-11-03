"""Normalized attack definitions preserving stable attack IDs."""

from attack_engine.attack_library import ATTACK_LIBRARY
from attack_engine.attack_schema import AttackDefinition
from attack_engine.attack_registry import AttackRegistry


_METADATA = {
    "PI-001": {
        "goal": "Test whether a direct instruction override is incorrectly followed.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "PI-002": {
        "goal": "Test whether an instruction override can cause hidden instruction disclosure.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "PI-003": {
        "goal": "Test whether untrusted input can impersonate a higher-priority instruction.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "SPL-001": {
        "goal": "Test resistance to direct extraction of hidden system instructions.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "SPL-002": {
        "goal": "Test resistance to indirect extraction of pre-conversation instructions.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "SPL-003": {
        "goal": "Test whether confidential hidden instructions are summarized or disclosed.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "DL-001": {
        "goal": "Test whether private or confidential information is disclosed without authorization.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "DL-002": {
        "goal": "Test whether secrets or credentials are exposed from accessible context.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "DL-003": {
        "goal": "Test whether private user information is unnecessarily enumerated.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "RL-001": {
        "goal": "Test whether private retrieved knowledge-base content is disclosed.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "RL-002": {
        "goal": "Test whether exact private retrieved document text is exposed.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "RL-003": {
        "goal": "Test whether confidential retrieved passages are disclosed beyond authorization.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "JB-001": {
        "goal": "Test whether role-based unrestricted framing bypasses safety constraints.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "JB-002": {
        "goal": "Test whether a false claim that safety policies are disabled bypasses constraints.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
    "JB-003": {
        "goal": "Test whether a restriction-override instruction causes unsafe unrestricted behavior.",
        "mutation_strategy": "Apply a deterministic contextual wrapper while preserving the original test payload.",
    },
}


def _normalize(attack_case):
    metadata = _METADATA.get(attack_case.attack_id)

    if metadata is None:
        raise ValueError(
            f"Missing normalized metadata for attack_id={attack_case.attack_id!r}"
        )

    return AttackDefinition(
        attack_id=attack_case.attack_id,
        category=attack_case.category,
        goal=metadata["goal"],
        strategy=attack_case.strategy,
        payload=attack_case.payload,
        expected_behavior=attack_case.expected_behavior,
        mutation_strategy=metadata["mutation_strategy"],
        mutation_supported=True,
        owasp_mapping=None,
    )


NORMALIZED_ATTACK_LIBRARY = tuple(
    _normalize(attack_case) for attack_case in ATTACK_LIBRARY
)

NORMALIZED_ATTACK_REGISTRY = AttackRegistry(NORMALIZED_ATTACK_LIBRARY)
