# Vakros Agentic SOC — Agent Backend v0.3

Autonomous, multi-tier AI SOC platform powering `app.vakros.com`.
Pulls open alerts, triages them through a tiered AI reasoning pipeline,
and writes verdicts, cases, and containment actions back in real time.

## New in v0.3 — Enhanced AI SOC Architecture

| Module | Description | Inspired by |
|--------|-------------|-------------|
| `integrations/` | Vendor-neutral SIEM/EDR/case management layer | [ai-soc-agent](https://github.com/M507/ai-soc-agent) |
| `hitl/` | Human-in-the-loop approval gate for high-risk actions | [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) |
| `security/` | Agentic scanner — scans agents for OWASP LLM Top 10 issues | [agentic-radar](https://github.com/splx-ai/agentic-radar), [snyk/agent-scan](https://github.com/snyk/agent-scan) |
| `roles/` | YAML role profiles (SOC1/SOC2/Hunt) with capability scoping | [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) |
| `vulnerability/` | Autonomous vuln scanner for customer assets | [crossbow-agent](https://github.com/harishsg993010/crossbow-agent) |

## Tiered Agent Architecture

```
SOC1 Agent (triage) → SOC2 Agent (IR + containment) → SOC3 (complex/nation-state)
         ↓                        ↓
   TheHive Case              HITL Approval Gate
   Creation                  (app.vakros.com/approvals)
```

## Integration Support

Configure via env vars — no code changes needed to swap vendors:

```bash
VAKROS_SIEM=elastic      # or wazuh (default)
VAKROS_EDR=crowdstrike   # or wazuh (default)
VAKROS_CASE=iris         # or thehive (default)
```

## HITL Approvals

High-risk actions (isolate host, block IP) require human approval:

```python
from vakros_agent.hitl import HITLApprovalGate, RiskLevel

gate = HITLApprovalGate()
approved = await gate.request(
    action="isolate_host",
    params={"host": "WIN-CORP-01"},
    risk=RiskLevel.CRITICAL,
    justification="Ransomware — all file encryption IOCs confirmed",
)
if approved:
    await edr.isolate_host("WIN-CORP-01", reason="Ransomware containment")
```

## Security Scanning (CI/CD)

```bash
python -m vakros_agent.security.agent_scanner --scan-dir . --fail-on-high
```

---

## Quick Start

### 1. Install dependencies
```bash
cd vakros-agent
pip install -r requirements.txt
```

### 2. Configure environment
```bash
cp .env.example .env
# Fill in ANTHROPIC_API_KEY and SUPABASE_SERVICE_KEY
```

### 3. Run triage

```bash
# Dry run — fetch alerts, no agent calls, no DB writes
python triage_runner.py --dry-run --limit 5

# Live triage — 5 alerts (good for first test)
python triage_runner.py --limit 5

# Triage a specific alert by UUID
python triage_runner.py --alert-id <uuid>

# Triage all 50 demo alerts
python triage_runner.py --limit 50
```

---

## What the Agent Does

For each alert the agent:
1. Searches the knowledge base (MITRE ATT&CK + runbooks) for context
2. Looks up any IOCs (IPs, hashes) via VirusTotal / AbuseIPDB — with 24hr caching
3. Assesses severity and determines verdict
4. Writes verdict back to `alerts` table via `update_alert_triage` tool
5. Creates a ticket in `tickets` table for HIGH/CRITICAL true positives
6. Escalates CRITICAL alerts or low-confidence findings

### Verdict options
| Verdict | Meaning | DB action |
|---|---|---|
| `true_positive` | Real attack confirmed | status → `open` (HIGH/CRITICAL) or `in_progress` |
| `false_positive` | Known safe — no action needed | status → `closed` |
| `benign` | Legitimate activity, not a threat | status → `closed` |
| `needs_investigation` | Uncertain — human review required | status → `in_progress` |

---

## Demo Data

The database is pre-loaded with:
- **50 realistic alerts** across 10 attack categories
- **31 demo agents** (servers, workstations, cloud)
- **42 MITRE ATT&CK techniques** in the knowledge base

### Alert categories
| Category | Alerts | Max Severity |
|---|---|---|
| Ransomware chain | 4 | 15/15 |
| APT campaign | 1 | 15/15 |
| DCSync / Golden Ticket | 2 | 15/15 |
| AWS root login / CloudTrail disabled | 2 | 15/15 |
| Phishing → account compromise | 3 | 14/15 |
| Credential dumping / Pass-the-Hash | 2 | 14/15 |
| Brute force | 4 | 13/15 |
| Lateral movement / Exfiltration | 5 | 13/15 |
| CVE exploitation | 3 | 15/15 |
| Insider threat | 3 | 13/15 |
| Benign / False positives | 6 | 6/15 |
| Network attacks | 3 | 12/15 |
| Compliance violations | 3 | 10/15 |
| C2 / Persistence | 5 | 12/15 |

---

## Architecture

```
triage_runner.py
    └── soc_agent.py          # Claude agent loop (tool_use, max 8 iterations)
         └── tools.py         # 8 tools:
              ├── search_knowledge_base   → mitre_techniques + documents tables
              ├── lookup_ioc              → ioc_cache → VirusTotal + AbuseIPDB
              ├── get_alert_context       → alerts table
              ├── update_alert_triage     → writes verdict to alerts + agent_actions
              ├── create_ticket           → tickets table
              ├── escalate_incident       → escalations table
              ├── list_recent_alerts      → alerts table
              └── get_agent_info          → agents table
```

---

## Supabase Tables

| Table | Purpose |
|---|---|
| `alerts` | Source alerts from Wazuh/SIEM |
| `agents` | Monitored hosts/endpoints |
| `agent_actions` | Audit log of every agent decision |
| `mitre_techniques` | 42 seeded ATT&CK techniques |
| `documents` | RAG knowledge base (runbooks, etc.) |
| `ioc_cache` | 24hr TTL cache for IOC lookups |
| `tickets` | Incident tickets created by agent |
| `playbooks` | Automated response playbooks |
| `soc_metrics` | Operational metrics |

---

## Seeding MITRE ATT&CK (full dataset)

The 42 priority techniques are pre-loaded. To load the full ~800-technique ATT&CK dataset, run `seed_mitre.py` from an environment with outbound internet access (not required for demo):

```bash
python seed_mitre.py            # All techniques
python seed_mitre.py --priority-only   # Just the 42 priority ones
```

