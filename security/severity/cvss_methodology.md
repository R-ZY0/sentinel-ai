# Sentinel AI - CVSS v4.0 Severity Methodology



## Purpose



Sentinel AI uses CVSS v4.0 to communicate the severity of confirmed security findings.



CVSS describes vulnerability severity. It is not a complete measurement of organizational risk.



## CVSS Version



Sentinel AI uses CVSS version 4.0.



Official source:



https://www.first.org/cvss/v4.0/



Specification:



https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf



## CVSS Metric Groups



CVSS v4.0 defines:



1. Base Metrics

2. Threat Metrics

3. Environmental Metrics

4. Supplemental Metrics



## Qualitative Severity Rating



| Score | Rating |

|---|---|

| 0.0 | None |

| 0.1 - 3.9 | Low |

| 4.0 - 6.9 | Medium |

| 7.0 - 8.9 | High |

| 9.0 - 10.0 | Critical |



## Sentinel AI Rule



Detection confidence must not be treated as CVSS severity.



For example:



confidence = 0.94



does not automatically mean:



CVSS = Critical



Detection confidence and vulnerability severity are separate values.



## Finding Lifecycle



Attack

-> Target Response

-> Evidence

-> Analyzer / Judge

-> Potential Finding

-> Confirmation / Retest

-> Confirmed Finding

-> CVSS Assessment

-> Final Severity



A final CVSS score should be assigned after the vulnerability has been sufficiently confirmed and the applicable CVSS metrics have been assessed.



## Score Representation



A vulnerability mapping should store:



- CVSS version

- CVSS score

- CVSS qualitative rating

- CVSS vector



Example:



CVSS version: 4.0

Score: 0.0

Rating: None

Vector: CVSS:4.0/...



## Current Test Cases



TC-001 System Prompt Leakage - Pending CVSS assessment



TC-002 Canary Secret Leakage - Pending CVSS assessment



TC-003 RAG Document Leakage - Pending CVSS assessment



TC-004 Synthetic PII Leakage - Pending CVSS assessment



TC-005 Prompt Injection to Leakage - Pending CVSS assessment



## Official References



FIRST CVSS v4.0:

https://www.first.org/cvss/v4.0/



FIRST CVSS v4.0 Specification:

https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf
