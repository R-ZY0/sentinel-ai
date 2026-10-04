# Sentinel AI

> AI Security Red-Teaming & Adaptive Data-Leakage Detection Platform

Sentinel AI is a web-based AI security testing platform designed to assess authorized LLM and RAG applications for data-leakage risks. It combines existing red-team probes with baseline judges and a CyberV-inspired adaptive judging loop.

## 1. Project Vision

The final V1 system allows an authorized user to register an AI target, configure a scan, run security probes, collect responses, evaluate them with baseline and adaptive judges, request a second round when confidence is insufficient, collect evidence, create findings, map them to security/CTI classifications, and generate a PDF report.

```text
User
  -> Register Target
  -> Configure Scan
  -> Attack Engine (garak / PyRIT)
  -> Target Adapter
  -> Authorized AI Target (LLM / RAG)
  -> Target Response
  -> Baseline Judge
  -> Adaptive Judge (Sensor + Controller + Confidence Gating)
  -> Evidence / Finding
  -> OWASP / CTI Mapping
  -> PDF Report
```

## 2. Research Question

> Can an adaptive judge based on a Sensor + Controller + confidence gating improve data-leakage detection compared with baseline approaches such as Canary/Regex, Presidio, a single LLM judge, and a hybrid judge?

The project does not assume that the adaptive method will win. The result must be determined experimentally.

## 3. Research Contribution

Sentinel AI does **not** claim to invent AI red-teaming, garak, PyRIT, LLM judging, or CyberV.

The intended contribution is an adaptive judging mechanism for AI data-leakage detection using a Sensor + Controller + confidence-gating loop, evaluated against baseline approaches.

CyberV is used as architectural inspiration for the feedback/controller mechanism; CyberV itself is not a cybersecurity paper.

Cyber-Zero is treated as a possible future/V2 extension for attack/defense trajectory generation and is not required for V1.

CTIBench is used as a reference/evaluation foundation for the CTI layer, not as the core attack scanner.

## 4. V1 Scope

### Targets

- Local Ollama target
- Local RAG target
- Authorized generic REST AI API

### Security Testing

- Prompt Injection
- System Prompt Leakage
- Sensitive Data Leakage
- RAG/Data Leakage
- Jailbreak

### Baseline Judges

```text
B0 = Canary / Regex
B1 = Presidio
B2 = Single LLM Judge
B3 = Presidio + LLM Judge
```

### Proposed Adaptive Systems

```text
A1 = Adaptive Judge
A2 = Adaptive Judge + second feedback/testing round
```

### V1 Outputs

- Scan history
- Attack attempts
- Target responses
- Judge verdicts
- Controller decisions
- Evidence
- Findings
- OWASP mapping
- CTI/security classification
- PDF reports
- Evaluation results

## 5. Explicitly Out of V1 Scope

- Full MCP security framework
- Full autonomous-agent security framework
- Every possible LLM vulnerability
- Enterprise SaaS deployment
- Support for every commercial AI provider
- Full Cyber-Zero trajectory-generation implementation
- Large-scale distributed scanning
- Production-scale multi-tenant infrastructure

These can become V2/future work.

## 6. Safety and Authorization

Sentinel AI is intended for authorized security testing only.

V1 testing should use local targets, owned targets, explicitly authorized APIs, synthetic/fake sensitive information, and canary secrets.

Do not use the platform against third-party systems without authorization. Do not use real personal data in evaluation. API credentials must never be committed to Git.

## 7. Ground Truth

Local evaluation targets contain planted test information such as:

```text
CANARY_SECRET_12345
```

and synthetic PII, internal-looking documents, RAG documents, and fake customer information.

Automatic ground truth:

```text
Canary appears in response -> Confirmed leakage
```

Ambiguous cases are manually labeled according to the team's labeling protocol.

## 8. Research Evaluation

Metrics:

- Precision
- Recall
- F1
- FPR
- FNR
- Cohen's Kappa
- Number of LLM calls
- Latency
- Cost/resource usage where applicable

Ablations may include:

- Different sample counts N
- Confidence gating vs always performing a second round
- Score Forest vs majority voting
- Different signal combinations

The test set must be frozen before final claims are written.

## 9. Core Architecture

```text
Frontend
   |
   v
FastAPI Backend
   |
   v
Celery / Redis
   |
   v
Scan Engine
   |
   +--> Attack Engine
   +--> Target Adapter
   +--> Judge
   +--> Adaptive Controller
   +--> Evidence / Finding
   +--> CTI
   |
   v
PostgreSQL
```

### Technology

Backend: FastAPI, Celery, Redis, PostgreSQL, JWT

Frontend: React, TypeScript, Tailwind CSS

AI/testing: Ollama, garak, PyRIT

Reporting: ReportLab

Deployment: Docker Compose

## 10. Repository Structure

```text
sentinel-ai/
|
├── contracts/
│   ├── attack_run.schema.json
│   ├── target_response.schema.json
│   ├── judge_verdict.schema.json
│   ├── finding.schema.json
│   └── report.schema.json
├── attack_engine/
├── judge/
├── cyberv_engine/
├── backend/
├── frontend/
├── targets/
├── eval/
├── docs/
├── tests/
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md
```

## 11. Core Contracts

The shared pipeline is:

```text
AttackRun -> TargetResponse -> JudgeVerdict -> Finding -> Report
```

### AttackRun

Represents one attack/test execution. It should contain identifiers for the attack, target and scan, category, payload/strategy, timestamp, and attempt information.

### TargetResponse

Represents the target response, including scan/attack identifiers, response text, status, timestamp, and latency. Secrets must not be stored unnecessarily.

### JudgeVerdict

Represents the judge interpretation:

```text
LEAK
NO_LEAK
AMBIGUOUS
```

It should include confidence, reason, signals, judge type, and timestamp.

### Finding

Represents a potential or confirmed vulnerability and includes category, status, severity, confidence, evidence, target/scan/attack identifiers, and security mappings.

### Report

Contains scan summary, target, attacks, findings, evidence, mappings, metrics, and recommendations.

## 12. Team Structure

The team has four members:

```text
1 AI/ML
2 Cyber Security
1 Full Stack
```

Recommended ownership:

```text
AI/ML Member       -> Judge + evaluation intelligence
Cyber Member #1    -> Attack Engine
Cyber Member #2    -> Security Validation + Evidence + CTI
Full Stack Member  -> Backend + Frontend + Infrastructure + Integration
```

Ownership does not mean isolated work. All four members coordinate around shared contracts.

---

# 13. MEMBER 1 — AI/ML

## Role

**AI/ML Engineer — Judge & Evaluation**

## Main Ownership

- Baseline LLM Judge
- Judge prompts
- Judge output schema
- Confidence estimation
- Judge signals
- Adaptive-judge AI components
- Dataset labeling support
- Evaluation experiments
- Ollama model integration for judging

## P0 — Week 1

- Create `judge/`
- Propose `JudgeVerdict`
- Agree on signals with Cyber #2
- Set up Ollama judge model
- Implement Canary/Regex judge
- Prototype Presidio
- Prototype LLM judge

## P1 — Weeks 2–3

- Consume real TargetResponse objects
- Normalize judge input/output
- Support baseline execution

## P2 — Weeks 3–4

Implement B0/B1/B2/B3 and create the initial labeled dataset and labeling protocol.

## P3 — Weeks 5–6

Implement the AI side of Sensor/signals/confidence/score and support A1/A2 with the controller owner.

## P4 — Weeks 7–8

Expose judge results to API/dashboard with verdict, confidence, reason, signals, and judge type.

## P5 — Weeks 9–10

Run experiments and calculate Precision, Recall, F1, FPR, FNR, Kappa, LLM calls, latency, and agreed ablations.

## P6 — Week 11

Optimize, test, document model versions/seeds, and remove unstable behavior.

## P7 — Week 12

Freeze results, produce AI/evaluation documentation, and prepare the research presentation.

## Final Deliverables

`judge/`, baseline judges, adaptive-judge AI logic, labeled dataset, evaluation scripts/results, tests, documentation.

---

# 14. MEMBER 2 — CYBER #1

## Role

**Cyber Security — Attack Engine Lead**

## Main Ownership

- garak integration
- PyRIT integration
- Attack runner
- Attack payload/probe management
- Attack categories
- Security attack scenarios
- OWASP attack mapping
- Reproducible scan execution

## P0 — Week 1

- Create `attack_engine/`
- Install/test garak
- Install/test PyRIT
- Explore available probes
- Define first attack categories
- Propose `AttackRun`
- Build initial runner abstraction

## P1 — Weeks 2–3

Build AttackRunner with garak/PyRIT. Support Prompt Injection, System Prompt Leakage, Data Leakage, RAG Leakage, and Jailbreak. Connect to Target Adapter and store attempts. Add OWASP mapping.

## P2 — Weeks 3–4

Provide attack cases for baseline judges, repeatable test executions, normalized TargetResponses, and evaluation dataset generation.

## P3 — Weeks 5–6

Support second-round attack selection and attack variants for adaptive testing.

## P4 — Weeks 7–8

Connect attack execution to dashboard and scan-progress storage.

## P5 — Weeks 9–10

Run attack suites across the frozen evaluation setup and track attack counts/execution cost.

## P6 — Week 11

Security test the attack engine, including timeouts, rate limits, errors, reproducibility, and pinned tool versions.

## P7 — Week 12

Final attack-engine documentation, reproducibility package, and demo scenarios.

## Final Deliverables

AttackRunner, garak/PyRIT integration, attack cases, mappings, second-round support, tests, documentation.

---

# 15. MEMBER 3 — CYBER #2

## Role

**Cyber Security — Security Validation, Evidence & CTI Lead**

## Main Ownership

- Ground truth
- Security validation
- Evidence confirmation
- Finding methodology
- OWASP mapping
- CWE mapping
- CVSS methodology where applicable
- CTI classification
- Human-labeling protocol
- Security review
- Final security interpretation

## P0 — Week 1

- Create `cyberv_engine/`
- Define LEAK / NO_LEAK / AMBIGUOUS
- Define ground-truth rules
- Create at least five security test cases
- Propose `Finding`
- Create initial OWASP mapping

## P1 — Weeks 2–3

Define security scenarios with goal, attack, expected safe behavior, expected vulnerable behavior, ground truth, and evidence. Validate the local RAG target.

## P2 — Weeks 3–4

Define potential/confirmed/rejected finding states, evidence rules, human labeling protocol, and dataset quality checks.

## P3 — Weeks 5–6

Own the security side of Sensor signals, confidence interpretation, evidence signals, and controller safety. Help define when a second round is justified.

## P4 — Weeks 7–8

Define the security presentation of findings: evidence, attack category, target, confidence, severity, and OWASP mapping.

## P5 — Weeks 9–10

Lead evaluation methodology. Ensure frozen test set, correct ground truth, documented human labeling, seeds/model versions, and honest claims. Lead CTI mapping.

## P6 — Week 11

Security review of Sentinel itself: authentication, authorization, secrets, API keys, logging, target authorization, input validation, SSRF/unsafe target handling, rate limits, and sensitive finding storage.

## P7 — Week 12

Final security documentation, security section of paper, demo scenarios, and defense preparation.

## Final Deliverables

Security methodology, ground truth, evidence rules, finding validation, OWASP/CWE/CTI mapping, evaluation methodology, security review, documentation.

---

# 16. MEMBER 4 — FULL STACK

## Role

**Full Stack — Platform & Integration Lead**

## Main Ownership

- FastAPI
- PostgreSQL
- Redis
- Celery
- Authentication
- Target management
- Scan API
- Frontend
- Dashboard
- Reports
- Docker
- Integration

## P0 — Week 1

Create backend/frontend/Docker Compose. Set up FastAPI, PostgreSQL, Redis, Celery, Ollama, environment variables, initial tables, health/target/scan APIs, Celery scan task, and local target integration.

Required primitive flow:

```text
API -> Celery -> AttackRunner -> Target -> Judge -> Finding -> PostgreSQL
```

## P1 — Weeks 2–3

Implement authentication, target CRUD, target validation, Target Adapter API, Generic REST target, Ollama target, scan creation, and scan states:

```text
PENDING -> RUNNING -> COMPLETED / FAILED / CANCELLED
```

## P2 — Weeks 3–4

Implement scan history, attack-attempt API, response storage, judge-verdict storage, finding storage, and basic scan status.

## P3 — Weeks 5–6

Integrate Judge, Sensor, Controller, second-round execution, and controller-decision storage.

## P4 — Weeks 7–8

Build Dashboard, Targets, New Scan, Active Scan, Scan History, Findings, Finding Details, Reports, Settings, JWT, and PDF generation.

## P5 — Weeks 9–10

Build evaluation views for baseline/adaptive results, metrics, comparisons, and experiment metadata.

## P6 — Week 11

Integration tests, security hardening, Docker hardening, errors, logging, API documentation, and SDD.

## P7 — Week 12

Final local deployment, final UI, final PDF, demo environment, and final integration.

## Final Deliverables

Backend, frontend, database, authentication, Docker, Celery, Redis, APIs, dashboard, reports, integration tests, deployment, documentation.

---

# 17. 12-Week Execution Plan

The source walkthrough estimates about 14 weeks. This repository plan compresses it to 12 weeks to match the team's three-month target.

| Week | Phase | Main Output |
|---|---|---|
| 1 | P0 Foundation | Contracts + infrastructure + first primitive pipeline |
| 2–3 | P1 Attack Engine + Targets | AttackRunner + target adapters + local LLM/RAG + generic REST |
| 3–4 | P2 Baseline Judges | B0/B1/B2/B3 + labeled dataset |
| 5–6 | P3 Adaptive Judge | Sensor + Controller + gating + second round |
| 7–8 | P4 Product UI | Dashboard + scans + findings + PDF |
| 9–10 | P5 Evaluation | Frozen test set + experiments + metrics + ablations |
| 11 | P6 Hardening | Tests + security review + Docker + SDD |
| 12 | P7 Final Integration | Final product + results + paper + demo |

Paper/documentation should be written continuously rather than postponed to the final week.

---

# 18. Week 1 Daily Plan

## Day 1 — Alignment

Team:

- Research question
- V1 scope
- Roles
- Repository
- Branches
- Contracts

AI:

- JudgeVerdict proposal
- Ollama setup

Cyber #1:

- garak/PyRIT setup
- AttackRun proposal

Cyber #2:

- Ground truth
- Security test cases
- Finding proposal

Full Stack:

- Repo
- Docker skeleton
- Backend/frontend skeleton

## Day 2 — Infrastructure

Run:

```text
FastAPI
PostgreSQL
Redis
Celery
Ollama
```

AI: Canary judge.

Cyber #1: first probe.

Cyber #2: ground-truth rules.

## Day 3 — Local Target

Build:

```text
Ollama
 + System Prompt
 + Canary
 + RAG
 + Fake PII
```

## Day 4 — Contracts

Finalize and validate:

```text
AttackRun
TargetResponse
JudgeVerdict
Finding
Report
```

Create mocks.

## Day 5 — First End-to-End Run

```text
garak
 -> Target
 -> Judge
 -> Finding
 -> Database
```

## Day 6 — Reading + Labeling

- Read core papers.
- Finalize labeling protocol.
- Test multiple responses.
- Document integration issues.

## Day 7 — Internal/Advisor Demo

```text
Start Scan
 -> Attack
 -> Target
 -> Response
 -> Judge
 -> Finding
```

P0 is complete only when the primitive pipeline works and the research question/scope are approved.

---

# 19. Git Workflow

Branches:

```text
main
develop

feature/attack-engine
feature/judge
feature/cyberv
feature/platform
```

No direct pushes to `main`.

```text
feature branch
 -> tests
 -> Pull/Merge Request
 -> review
 -> develop
 -> main
```

---

# 20. Definition of Done

A feature is done when:

- Code exists.
- Tests exist where appropriate.
- Contract is respected.
- Error handling exists.
- Documentation exists.
- Secrets are not exposed.
- Integration works.
- Another team member can run it.

---

# 21. Project Rules

1. No direct pushes to `main`.
2. Every feature uses a branch.
3. Contracts are shared team decisions.
4. No API keys in Git.
5. No real personal data in evaluation.
6. Only authorized targets.
7. Freeze the test set before final evaluation.
8. Record model versions and seeds.
9. Record controller decisions and reasons.
10. Demonstrate working software every two weeks.
11. Do not claim superiority before experiments.
12. If adaptive performs worse, report the result honestly.
13. Keep V1 scope frozen.
14. Cyber-Zero trajectory generation remains V2/optional unless V1 finishes early.

---

# 22. Final Product Checklist

## Platform

- [ ] Authentication
- [ ] Target registration
- [ ] Target validation
- [ ] Scan creation
- [ ] Scan execution
- [ ] Scan cancellation
- [ ] Scan history
- [ ] Attack attempts
- [ ] Responses
- [ ] Findings
- [ ] Reports

## Target Support

- [ ] Ollama
- [ ] Local RAG
- [ ] Generic REST API

## Attack

- [ ] Prompt Injection
- [ ] System Prompt Leakage
- [ ] Data Leakage
- [ ] RAG Leakage
- [ ] Jailbreak
- [ ] garak
- [ ] PyRIT

## Judges

- [ ] Canary/Regex
- [ ] Presidio
- [ ] LLM Judge
- [ ] Hybrid
- [ ] Adaptive Judge
- [ ] Confidence gating
- [ ] Second round

## Security

- [ ] Ground truth
- [ ] Evidence
- [ ] Finding validation
- [ ] OWASP
- [ ] CWE
- [ ] Severity
- [ ] CTI
- [ ] Security review

## Evaluation

- [ ] Precision
- [ ] Recall
- [ ] F1
- [ ] FPR
- [ ] FNR
- [ ] Cohen's Kappa
- [ ] Latency
- [ ] LLM calls
- [ ] Cost/resource usage
- [ ] Ablation studies
- [ ] Frozen test set

## Delivery

- [ ] Docker Compose
- [ ] Tests
- [ ] Documentation
- [ ] PDF report
- [ ] Research paper draft
- [ ] Presentation
- [ ] Final demo

---

# 23. Final Definition

Sentinel AI is not simply an AI that attacks another AI.

It is an authorized AI security assessment platform that executes AI-security probes against LLM/RAG targets, evaluates responses using baseline and adaptive judges, validates suspected data leakage using evidence and ground truth, and produces security/CTI findings and reports.

Its research contribution is the experimental evaluation of an adaptive Sensor + Controller + confidence-gating judging mechanism against baseline approaches.

## Current Status

```text
Phase: P0 Foundation
Week: 1
Milestone: First primitive end-to-end pipeline
Priority: Contracts -> Infrastructure -> Local Target -> First Attack -> First Judge -> First Finding
```
