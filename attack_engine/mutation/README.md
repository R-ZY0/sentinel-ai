# Week 5 — deterministic attack variants

This opt-in module generates reproducible, traceable variants for **authorized**
security tests. It does not alter `AttackDefinition`, `AttackRun`, existing
`attack_mutator.py`, or the Week 3–4 default execution path.

## API

```python
from attack_engine.mutation import VariantGenerator

variants = VariantGenerator().generate(
    definition, seed=42, count=2, used_payloads=prior_payloads
)
```

`definition` is the existing `AttackDefinition`, with
`mutation_supported=True`. The return value is a list of immutable
`AttackVariant` records. Each record includes its distinct `attack_id`,
`parent_attack_id`, category, goal, strategy, expected behavior, payload,
mutation strategy, seed, index, and canonicalized SHA-256 payload fingerprint.

Available strategies: `contextual_wrapper`, `structured_request`, and
`dialogue_context`. They preserve the original payload verbatim and modify
its framing. These are **textual** variations, not proof of semantic novelty
or increased attack effectiveness.

The caller must provide previous payloads in `used_payloads` for cross-process
deduplication. Failure to produce enough distinct variants raises
`MutationError` (fail-closed); no external target is invoked.

## Dependencies and tests

Only Python standard-library modules and the existing AttackDefinition are
required. From the repository root:

```powershell
python -m pytest attack_engine/test_week5_mutation.py -q
python -m pytest attack_engine/test_attack_schema.py attack_engine/test_normalized_execution.py -q
```

## Integration contract for Week 6

The Controller/Full Stack owner must agree on the envelope linking an
`AttackVariant` to the actual database attempt UUID, scan/target identifiers,
execution outcome, and response. `parent_attack_id` refers to the source
*attack definition*, not a database attempt ID. This module does not insert
database rows, modify shared contracts, retry targets, or select a new target.
Its payload fingerprint is for deduplication, not for integrity attestation.

Known limits: three fixed templates; no model-based paraphrasing; identical
payloads are detected using whitespace-normalized, case-folded text, not
semantic similarity. The optional seeded ordering is reproducible under the
same Python runtime. The Week 6 bounded orchestration is a separate task.
