# NIST AI RMF Audit Evidence

Reference: https://www.nist.gov/itl/ai-risk-management-framework

## Framework Documents
- [NIST AI 100-1 (AI RMF 1.0)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) — January 2023
- [NIST AI 600-1 (GenAI Profile)](https://doi.org/10.6028/NIST.AI.600-1) — July 2024
- [AI RMF Critical Infrastructure Profile](https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure) — April 2026
- [AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)

## Directory Structure

```
nist-ai-rmf/
├── govern/      # GV-1.1, GV-1.2, GV-2.2, GV-4.1, GV-4.2, GV-6.1
│               # Policies, accountability, risk tolerance, culture
├── map/         # MP-1.1, MP-2.1, MP-2.2, MP-3.5, MP-4.1, MP-5.2
│               # System context, risk identification, TEVV plans
├── measure/     # MS-1.1, MS-2.2, MS-2.5, MS-2.6, MS-2.7, MS-2.10, MS-3.3, MS-4.1
│               # Risk metrics, bias, explainability, security, privacy, TEVV results
└── manage/      # MG-1.1, MG-2.2, MG-2.4, MG-3.1, MG-4.1, MG-4.2
                # Risk response, incident handling, residual risk, postmortem
```

## Evidence Naming Convention

Files in each subdirectory follow: `YYYY-MM-DD_<control-id>_<description>.json`

Example: `2026-06-17_MS-2.7_agent-security-scan-results.json`

## What Goes Here

| Sub-dir | Evidence Type |
|---|---|
| govern/ | AI risk policy docs, accountability role assignments, risk tolerance configs |
| map/ | AI system cards, risk taxonomies, TEVV test plans, impact assessments |
| measure/ | TEVV results, bias/fairness reports, security scan outputs, confidence score logs |
| manage/ | Risk response plans, incident reports, postmortems, residual risk logs |

The `compliance_gate.py` Stage 8 check verifies these directories exist and are populated.
