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