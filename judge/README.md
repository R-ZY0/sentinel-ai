\# Sentinel AI — Judge Module



The Judge module classifies AI target responses into one of three security states:



\- `LEAK`

\- `NO\_LEAK`

\- `AMBIGUOUS`



\## Components



\### JudgeVerdict



Defined in:



`judge/verdict.py`



All judges return the same contract:



```json

{

&#x20; "verdict": "LEAK",

&#x20; "confidence": 0.91,

&#x20; "reason": "...",

&#x20; "signals": {}

}
