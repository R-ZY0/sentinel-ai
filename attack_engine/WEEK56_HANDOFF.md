# Sentinel AI — Attack Engine Weeks 5–6 Handoff

## Ownership
Cybersecurity Member #1 — Attack Engine

## Base
release/week-03-04
Base commit: 7d62723

## Branch
feature/attack-engine-week5-week6

## Week 5
- Deterministic attack variants
- Multiple mutation strategies
- Parent attack tracking
- Reproducible seed handling
- Duplicate payload prevention
- Mutation unit tests

## Week 6
- Controller-requested second-round execution
- ACCEPT / SECOND_ROUND / STOP handling
- Bounded attempt execution
- Target and attempt-history checks
- Synchronous and asynchronous runner support
- Timeout and execution-error handling
- Failed executions marked not_evaluated

## Compatibility
Existing AttackRun and shared contracts remain unchanged.
Existing Week 3–4 execution entry points remain unchanged.
All new functionality is opt-in.

## Test Environment
Python 3.12.1
Pytest 8.3.4

## Verified Results
Core, Week 5/6 and regression selection:
72 passed

Backend and execution contract selection:
23 passed

Total across these two test selections:
95 passed

## Limitations
- Full optional PyRIT and Garak suites were not completed
  in this local environment because their dependencies
  require separate tool environments.
- Docker end-to-end adaptive pipeline was not verified.
- Controller/API/Celery integration is owned by Full Stack.
- No production target was tested.
- Mutation strategies are deterministic textual
  variations, not semantic adversarial optimization.

## Integration Requirements
Full Stack must map AttackVariant and AttackRun into
persisted scan/target/attempt context.

Authorization must be verified by server-controlled logic.

The Controller must provide the decision and complete
attempt history before requesting another round.

Security Validation must verify evidence independently
before any Finding is confirmed.

## Shared Contract Changes
None.

## Files Added
- attack_engine/mutation/
- attack_engine/adaptive/
- attack_engine/test_week5_mutation.py
- attack_engine/test_week6_second_round.py
- attack_engine/WEEK56_HANDOFF.md

## Pending
- Team interface review
- Optional scanner integration tests
- Docker end-to-end adaptive loop
- Pull Request review and merge
