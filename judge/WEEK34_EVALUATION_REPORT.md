\# Sentinel AI — AI/ML Week 3 \& Week 4 Evaluation Report



\## 1. Scope



This report covers judge-local AI/ML work for Weeks 3 and 4.



All implemented changes are restricted to `judge/`.



The existing Week 2 judge implementations and shared contracts

are preserved. The new Week 3 judge is not automatically integrated

into the backend or security validation pipeline.



All evaluations are advisory only.



\## 2. Week 3 — LLM Judge



Implemented:



\- `week3\\\_prompt.py`: standalone system prompt and structured input.

\- `week3\\\_llm\\\_judge.py`: local Ollama-based LLM judge.

\- `trusted\\\_evidence.py`: exact-match verification against trusted references.

\- Structured output using the existing JudgeVerdict contract.

\- LEAK, NO\_LEAK, and AMBIGUOUS classifications.

\- Confidence, reason, signals, and evaluator-owned metadata.

\- Error handling that returns AMBIGUOUS instead of claiming safety.

\- Model configuration with temperature 0 and seed 42.



Model: `llama3.2:3b`

Host: `http://localhost:11434`



Trusted references must originate from evaluator-controlled sources.

Values from attacker-controlled prompts must never be promoted to

trusted references.



\## 3. Week 4 — Dataset Work



Implemented:



\- JailbreakBench artifact loaders, including batch loading.

\- Leakage label validation and JSON dataset loading.

\- Controlled synthetic TC-001 through TC-005 fixtures.

\- Dataset unit tests.

\- Evaluation scripts and saved result reports.



External JailbreakBench artifacts:



\- JSON files examined: 18

\- Total records: 1,800

\- Usable records: 1,637

\- Skipped records: 163

\- Unique case IDs: 1,637



These records have jailbreak-related labels, not verified leakage

ground truth. Jailbreak success must NOT be mapped automatically

to LEAK or NO\_LEAK.



Raw external datasets remain outside the repository.

Source licenses and access restrictions must be reviewed before

any redistribution or expanded use.



\### Synthetic leakage dataset



File: `judge/datasets/tc\\\_week34\\\_synthetic.json`



Total: 10 controlled cases covering TC-001 through TC-005.



The cases include:



\- Safe refusals

\- Canary disclosure

\- Synthetic protected-document disclosure

\- Synthetic customer-data disclosure

\- Prompt-injection-related canary disclosure

\- Ambiguous secret-existence response



Dataset fields include test\_case\_id, attack\_type, attack,

response, expected\_behavior, ground\_truth, evidence\_rule,

severity, and source.



The current severity value `UNASSESSED` is a placeholder,

not a validated risk rating.



TC-001 currently has a safe test fixture only. No trusted

system-prompt leak fixture is available for confirmed matching.



Ground-truth labels, evidence rules, and severity decisions

require review with the Cybersecurity team.



\## 4. Synthetic Baseline Comparison



| Judge | Matching cases | Match rate |

|---|---:|---:|

| B0 | 7/10 | 70% |

| B1 | 6/10 | 60% |

| B2 | 8/10 | 80% |

| B3 | 8/10 | 80% |

| Week3LLMJudge | 10/10 | 100% |



Baseline report:

`judge/eval/week34\\\_synthetic\\\_results.json`



Week 3 report:

`judge/eval/week3\\\_synthetic\\\_results.json`



The Week 3 judge received independently trusted references for

these controlled fixtures. The earlier baselines did not use

the same reference-assisted classification mechanism.



Therefore these figures are descriptive comparisons on the

same cases, not evidence of a generalizable accuracy improvement.



\## 5. Trusted Evidence Analysis



The Week 3 evaluation recorded no evaluation errors.



Exact trusted-reference matching was used for:



\- TC-002-LEAK: protected canary

\- TC-003-LEAK: protected synthetic document

\- TC-004-LEAK: protected synthetic customer fields

\- TC-005-LEAK: protected canary



The evidence verifier checks the target response, not the attack.



Full exact matches are case-sensitive. Short references and

partial matches are not treated as conclusive exact evidence.



Matched reference names are recorded, not raw protected values.



Confidence 1.0 from this evidence rule represents exact-match

certainty under the supplied synthetic reference, not certainty

of a real-world vulnerability.



\## 6. Testing



Command:



&#x20;   python -m unittest discover -s judge\\tests -v



Observed result:



&#x20;   Ran 56 tests

&#x20;   OK



The suite includes 29 new Week 3/4 tests and existing

Week 1/2 judge tests.



The following were also exercised against local Ollama:



\- Previous B0/B1/B2/B3 synthetic comparison.

\- Week 3 RAG and PII cases.

\- Week 3 evaluation across all 10 synthetic cases.



\## 7. Limitations and Known Risks



1\. Only 10 controlled synthetic cases were evaluated.

2\. Synthetic match rate is not production accuracy.

3\. Test cases reuse evaluator-known protected references.

4\. Exact matching does not cover all paraphrases, encodings,

&#x20;  partial disclosures, or real-world data variations.

5\. A generic document phrase could match outside its intended

&#x20;  provenance; evidence interpretation requires context.

6\. Model-only judgments can be incorrect or overconfident.

7\. An Ollama or schema failure results in AMBIGUOUS and

&#x20;  requires review, not a confirmed finding.

8\. Security-owned labels and severity remain pending review.

9\. No end-to-end backend integration or production scan

&#x20;  is claimed by this report.

10\. External jailbreak benchmarks are not leakage benchmarks.



\## 8. Handoff Requirements



Before production integration:



\- Obtain Security review of labels and evidence rules.

\- Agree on output-contract and integration requirements

&#x20; with the team lead.

\- Keep advisory verdicts separate from confirmed findings.

\- Evaluate against a larger, independently labeled leakage dataset.

\- Review reference provenance and protect sensitive values.

\- Run integration and regression tests after approved wiring.



\## 9. Delivery



Target branch: `feature/ai-judge-week-03-04`



Base branch: `release/week-02`



Delivery method: GitHub pull request for review.



Do not merge without team lead approval.



\## 10. External JailbreakBench Exploratory Evaluation



An exploratory evaluation was performed on external

JailbreakBench attack artifacts using Week3LLMJudge.



\### Dataset and sampling



\- Source: JailbreakBench/artifacts

\- Available usable records: 1,637

\- Evaluated sample: 24 records

\- Sampling seed: 42

\- Attack methods: DSN, GCG, JBC, PAIR,

&#x20; prompt\_with\_random\_search

\- Jailbreak labels: 12 JAILBROKEN, 12 NOT\_JAILBROKEN



The sample was selected across attack methods and

jailbreak labels. It is not statistically representative.



\### Judge results



| Judge verdict | Count |

|---|---:|

| NO\_LEAK | 13 |

| LEAK | 5 |

| AMBIGUOUS | 6 |

| Total | 24 |



Evaluation errors: 0



Output:

`judge/eval/jbb\_exploratory\_results.json`



\### Interpretation



JailbreakBench measures jailbreak success, not verified

disclosure of protected information.



Jailbreak labels must not be treated as leakage labels.



No trusted protected references were provided during

this evaluation.



The five LEAK classifications are unverified advisory

model judgments, not confirmed security findings.



No leakage accuracy, precision, recall, or false-positive

rate can be calculated from these labels.



No attacks were executed against a new target.

The report does not include raw attack prompts or

target responses.



The results demonstrate that the dataset loader and

Week 3 judge can process external artifacts, but do

not establish real-world leakage detection performance.



