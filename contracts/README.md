# Sentinel AI Contracts

This folder contains the shared data contracts used between the platform, attack engine, security validation, and reporting components.

## Core pipeline

```text
AttackRun -> TargetResponse -> JudgeVerdict -> Finding -> Report
```

## Ownership

- `backend/` produces and stores platform records.
- `attack_engine/` produces attack-run data.
- `security_validation/` produces validation evidence and verdicts.
- `contracts/` defines the shared formats connecting those components.

## Rules

- Changes to shared contracts require team agreement before implementation.
- Put example payloads in `examples/`.
- Keep contract changes backward-compatible unless the team plans a coordinated update.
- Never put real credentials or personal data in contract examples.

## Current status

The backend currently implements the initial Target and Scan API records plus stored attempts, responses, and findings. The complete shared schemas for `AttackRun`, `TargetResponse`, `JudgeVerdict`, `Finding`, and `Report` will be added after the responsible team members agree on their fields.

## Week 3–4 platform examples

`examples/week34-target-request.json` shows typed target registration;
`examples/week34-scan-request.json` and `examples/week34-scan-response.json`
show configuration and the new created-before-start flow. UUIDs are illustrative;
use IDs returned by your own API. These examples do not change the teammates'
shared attack/judge/finding contracts. See the
[backend guide](../docs/integration/week-03-04-backend.md) for compatibility details.
