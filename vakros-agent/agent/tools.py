"""
Vakros Agent Tools  —  v0.2
Tool definitions + implementations for the Claude triage agent.

Tools:
  search_knowledge_base   — semantic RAG over documents table
  lookup_ioc              — check IP/domain/hash against threat intel cache + external APIs
  get_alert_context       — fetch full alert record + related tickets from Supabase
  assess_severity         — structured CVSS-guided severity scoring
  suggest_remediation     — prioritised remediation plan
  create_ticket           — write incident ticket to Supabase tickets table
  update_alert_triage     — write triage verdict + summary back to alerts table
  escalate_incident       — flag for human analyst review
"""

import os
import json
import hashlib
import httpx
from datetime import datetime, timezone

from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
_sb = create_client(SUPABASE_URL, SUPABASE_KEY)

VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")

# ── Tool Definitions (passed to Claude API) ──────────────────────────────────

TOOLS = [
    {
        "name": "search_knowledge_base",
        "description": (
            "Search the Vakros security knowledge base for MITRE ATT&CK techniques, "
            "threat intel, CVEs, playbooks, and compliance controls. "
            "Always call this first when analysing an unfamiliar alert type."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Precise search query, e.g. 'brute force authentication T1110' or 'ransomware file extension detection'.",
                },
                "collection": {
                    "type": "string",
                    "enum": ["threat_intel", "compliance", "runbooks", "vendor_risk", "mitre"],
                    "default": "threat_intel",
                },
                "top_k": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "lookup_ioc",
        "description": (
            "Look up an IP address, domain, file hash (MD5/SHA256), or URL against "
            "threat intelligence sources. Returns verdict (malicious/suspicious/clean/unknown), "
            "confidence score, and threat tags. Results are cached for 24 hours."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "hash", "url", "email"],
                },
                "ioc_value": {
                    "type": "string",
                    "description": "The actual IOC to look up.",
                },
            },
            "required": ["ioc_type", "ioc_value"],
        },
    },
    {
        "name": "get_alert_context",
        "description": (
            "Fetch the full alert record from the database including all raw event data, "
            "asset info, and any prior triage history. Use when you need more detail "
            "than what was provided in the initial alert summary."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {
                    "type": "string",
                    "description": "UUID of the alert from the alerts table.",
                },
            },
            "required": ["alert_id"],
        },
    },
    {
        "name": "assess_severity",
        "description": (
            "Score the severity of a security finding using CVSS 3.1 criteria. "
            "Returns CRITICAL/HIGH/MEDIUM/LOW with structured rationale."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding": {"type": "string"},
                "asset_criticality": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "unknown"],
                    "default": "unknown",
                },
                "exploitability": {
                    "type": "string",
                    "enum": ["active", "poc_available", "theoretical", "none"],
                    "default": "theoretical",
                },
                "data_exposure": {
                    "type": "boolean",
                    "default": False,
                },
            },
            "required": ["finding"],
        },
    },
    {
        "name": "suggest_remediation",
        "description": (
            "Generate a prioritised remediation plan: immediate containment, "
            "short-term fixes, detection rules, and long-term preventive controls."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "environment": {"type": "string", "default": "cloud"},
            },
            "required": ["finding", "severity"],
        },
    },
    {
        "name": "update_alert_triage",
        "description": (
            "Write the triage verdict and analysis back to the alert record in the database. "
            "Call this as the FINAL action once you have a confident verdict."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "verdict": {
                    "type": "string",
                    "enum": ["true_positive", "false_positive", "benign", "needs_investigation"],
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                },
                "confidence": {
                    "type": "number",
                    "description": "0.0 to 1.0 confidence in the verdict.",
                },
                "summary": {
                    "type": "string",
                    "description": "2-4 sentence plain-English summary for the analyst.",
                },
                "mitre_techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Matched MITRE ATT&CK technique IDs e.g. ['T1110', 'T1078']",
                },
                "recommended_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["alert_id", "verdict", "severity", "confidence", "summary"],
        },
    },
    {
        "name": "create_ticket",
        "description": (
            "Create an incident ticket for confirmed true positives or findings "
            "requiring analyst follow-up."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "tenant_id": {"type": "string"},
                "summary": {"type": "string"},
                "priority": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                },
                "description": {"type": "string"},
            },
            "required": ["alert_id", "tenant_id", "summary", "priority"],
        },
    },
    {
        "name": "escalate_incident",
        "description": (
            "Flag for immediate human SOC analyst review. Use when: confidence < 0.6, "
            "severity is CRITICAL, novel attack pattern detected, or containment action needed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "incident_summary": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM"]},
                "reason_for_escalation": {"type": "string"},
            },
            "required": ["incident_summary", "severity", "reason_for_escalation"],
        },
    },
    {
        "name": "recall_attack_path",
        "description": (
            "Query the Vakros temporal knowledge graph to retrieve the attack path for "
            "a specific entity (host, IP, user, domain, hash, or MITRE technique). "
            "Returns every observed relationship and movement up to 2 hops away, with "
            "timestamps and originating alert IDs. Use this when you need to understand "
            "prior activity — e.g. 'Has this IP connected to any other hosts?' or "
            "'What has this host been doing over the past 30 days?' or "
            "'Is this part of a known campaign?'"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "entity_type": {
                    "type": "string",
                    "enum": ["host", "ip", "user", "technique", "campaign", "domain", "hash", "cve"],
                    "description": "The type of entity to look up.",
                },
                "entity_value": {
                    "type": "string",
                    "description": "The actual value, e.g. 'WIN-CORP-01', '185.220.101.5', 'T1486'.",
                },
                "tenant_id": {
                    "type": "string",
                    "description": "Tenant scope for the graph lookup.",
                },
                "max_hops": {
                    "type": "integer",
                    "description": "How many relationship hops to traverse (1 or 2).",
                    "default": 2,
                },
            },
            "required": ["entity_type", "entity_value", "tenant_id"],
        },
    },
]


# ── Tool Router ──────────────────────────────────────────────────────────────

def execute_tool(tool_name: str, tool_input: dict) -> str:
    try:
        if tool_name == "search_knowledge_base":
            return _search_knowledge_base(**tool_input)
        elif tool_name == "lookup_ioc":
            return _lookup_ioc(**tool_input)
        elif tool_name == "get_alert_context":
            return _get_alert_context(**tool_input)
        elif tool_name == "assess_severity":
            return _assess_severity(**tool_input)
        elif tool_name == "suggest_remediation":
            return _suggest_remediation(**tool_input)
        elif tool_name == "update_alert_triage":
            return _update_alert_triage(**tool_input)
        elif tool_name == "create_ticket":
            return _create_ticket(**tool_input)
        elif tool_name == "escalate_incident":
            return _escalate_incident(**tool_input)
        elif tool_name == "recall_attack_path":
            return _recall_attack_path(**tool_input)
        else:
            return f"ERROR: Unknown tool '{tool_name}'"
    except Exception as e:
        return f"ERROR executing {tool_name}: {str(e)}"


# ── Implementations ──────────────────────────────────────────────────────────

def _search_knowledge_base(query: str, collection: str = "threat_intel", top_k: int = 5) -> str:
    """Text search fallback (works before embeddings are seeded); MITRE direct lookup."""
    rows = []
    try:
        result = _sb.rpc("search_documents_text", {
            "search_query": query,
            "match_collection": collection,
            "match_count": top_k,
        }).execute()
        rows = result.data or []
    except Exception:
        pass

    if rows:
        parts = []
        for i, r in enumerate(rows, 1):
            parts.append(f"[{i}] {r.get('source', 'unknown')}\n{r['content'][:600]}")
        return "\n\n---\n\n".join(parts)

    # Direct MITRE table search
    mitre = _search_mitre_direct(query)
    if mitre:
        return mitre

    return f"No documents found in '{collection}' for: '{query}'. Knowledge base may not be seeded yet."


def _search_mitre_direct(query: str) -> str:
    q = query.lower()
    try:
        result = _sb.table("mitre_techniques") \
            .select("technique_id,name,tactic,description,detection") \
            .ilike("name", f"%{q}%") \
            .limit(3).execute()
        if not result.data:
            result = _sb.table("mitre_techniques") \
                .select("technique_id,name,tactic,description,detection") \
                .ilike("description", f"%{q}%") \
                .limit(3).execute()
        if result.data:
            parts = []
            for r in result.data:
                parts.append(
                    f"MITRE {r['technique_id']}: {r['name']}\n"
                    f"Tactics: {', '.join(r.get('tactic') or [])}\n"
                    f"Description: {(r.get('description') or '')[:400]}\n"
                    f"Detection: {(r.get('detection') or '')[:300]}"
                )
            return "\n\n---\n\n".join(parts)
    except Exception:
        pass
    return ""


def _lookup_ioc(ioc_type: str, ioc_value: str) -> str:
    ioc_value = ioc_value.strip().lower()

    # Check cache first
    try:
        cached = _sb.table("ioc_cache") \
            .select("*") \
            .eq("ioc_type", ioc_type) \
            .eq("ioc_value", ioc_value) \
            .gt("expires_at", datetime.now(timezone.utc).isoformat()) \
            .limit(1).execute()
        if cached.data:
            r = cached.data[0]
            return (
                f"IOC Cache Hit — {ioc_type.upper()}: {ioc_value}\n"
                f"Verdict: {r['verdict']} (confidence: {r['confidence']})\n"
                f"Threat tags: {', '.join(r.get('threat_tags') or []) or 'none'}\n"
                f"Sources: {json.dumps(r.get('sources', []))}"
            )
    except Exception:
        pass

    vt_result = _query_virustotal(ioc_type, ioc_value)
    abuse_result = _query_abuseipdb(ioc_value) if ioc_type == "ip" else {}
    verdict, confidence, tags = _compute_verdict(ioc_type, ioc_value, vt_result, abuse_result)

    try:
        _sb.table("ioc_cache").upsert({
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "verdict": verdict,
            "confidence": confidence,
            "sources": [
                {"source": "virustotal", **vt_result},
                *([{"source": "abuseipdb", **abuse_result}] if abuse_result else []),
            ],
            "threat_tags": tags,
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception:
        pass

    return (
        f"IOC Lookup — {ioc_type.upper()}: {ioc_value}\n"
        f"Verdict: {verdict} (confidence: {confidence:.0%})\n"
        f"Threat tags: {', '.join(tags) or 'none'}\n"
        f"VirusTotal: {vt_result.get('summary', 'N/A')}\n"
        f"AbuseIPDB: {abuse_result.get('summary', 'N/A') if abuse_result else 'N/A'}"
    )


def _query_virustotal(ioc_type: str, value: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"summary": "API key not configured — set VIRUSTOTAL_API_KEY", "malicious": 0, "total": 0}
    try:
        urls = {
            "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
            "hash":   f"https://www.virustotal.com/api/v3/files/{value}",
            "url":    f"https://www.virustotal.com/api/v3/urls/{hashlib.sha256(value.encode()).hexdigest()}",
        }
        url = urls.get(ioc_type)
        if not url:
            return {"summary": f"Unsupported type: {ioc_type}"}
        r = httpx.get(url, headers={"x-apikey": VIRUSTOTAL_KEY}, timeout=10)
        if r.status_code != 200:
            return {"summary": f"VT HTTP {r.status_code}", "malicious": 0, "total": 0}
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return {"malicious": mal, "total": total, "summary": f"{mal}/{total} engines flagged malicious"}
    except Exception as e:
        return {"summary": f"VT error: {e}", "malicious": 0, "total": 0}


def _query_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"summary": "API key not configured — set ABUSEIPDB_API_KEY", "score": 0}
    try:
        r = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if r.status_code != 200:
            return {"summary": f"AbuseIPDB HTTP {r.status_code}", "score": 0}
        d = r.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        return {
            "score": score,
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode", "??"),
            "summary": f"Abuse score {score}/100, {d.get('totalReports',0)} reports, country: {d.get('countryCode','??')}",
        }
    except Exception as e:
        return {"summary": f"AbuseIPDB error: {e}", "score": 0}


def _compute_verdict(ioc_type, value, vt, abuse) -> tuple:
    tags = []
    mal = vt.get("malicious", 0)
    total = vt.get("total", 0)
    abuse_score = abuse.get("score", 0) if abuse else 0

    if abuse_score >= 80:
        tags.append("high-abuse-score")
    if mal >= 10:
        tags.append("multi-engine-detection")
    if mal >= 3:
        tags.append("known-malicious")

    ratio = mal / max(total, 1)
    if ratio >= 0.3 or abuse_score >= 80:
        return "malicious", min(0.95, 0.6 + ratio * 0.5 + abuse_score / 400), tags
    elif ratio >= 0.05 or abuse_score >= 25:
        tags.append("suspicious")
        return "suspicious", 0.6, tags
    elif total > 0:
        return "clean", 0.8, tags
    else:
        return "unknown", 0.3, tags


def _get_alert_context(alert_id: str) -> str:
    result = _sb.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
    if not result.data:
        return f"Alert {alert_id} not found."
    a = result.data[0]
    tickets = _sb.table("tickets").select("id,summary,status,priority").eq("alert_id", alert_id).execute()
    ticket_info = f"\nExisting tickets: {json.dumps(tickets.data)}" if tickets.data else ""
    return (
        f"Alert ID: {a['id']}\n"
        f"Source: {a.get('source_platform', 'wazuh')}\n"
        f"Rule: {a.get('rule_desc', 'N/A')} (rule_id: {a.get('rule_id')})\n"
        f"Wazuh severity: {a.get('severity')}\n"
        f"Event type: {a.get('event_type', 'N/A')}\n"
        f"Agent: {a.get('agent_id', 'N/A')}\n"
        f"Occurred: {a.get('occurred_at')}\n"
        f"Status: {a.get('status')}\n"
        f"Prior verdict: {a.get('triage_verdict', 'none')}\n"
        f"Threat intel: {json.dumps(a.get('threat_intel')) if a.get('threat_intel') else 'none'}"
        f"{ticket_info}"
    )


def _assess_severity(
    finding: str,
    asset_criticality: str = "unknown",
    exploitability: str = "theoretical",
    data_exposure: bool = False,
) -> str:
    score = 0
    if asset_criticality in ("critical", "high"): score += 3
    elif asset_criticality == "medium": score += 2
    elif asset_criticality == "low": score += 1
    if exploitability == "active": score += 4
    elif exploitability == "poc_available": score += 3
    elif exploitability == "theoretical": score += 1
    if data_exposure: score += 2
    sev = "CRITICAL" if score >= 7 else "HIGH" if score >= 5 else "MEDIUM" if score >= 3 else "LOW"
    return (
        f"Severity Assessment:\n"
        f"Finding: {finding[:300]}\n"
        f"Asset criticality: {asset_criticality} | Exploitability: {exploitability} | Data exposure: {data_exposure}\n"
        f"Computed baseline: {sev} (score {score}/9)\n"
        f"[Apply CVSS 3.1: AV/AC/PR/UI/S/C/I/A to confirm]"
    )


def _suggest_remediation(finding: str, severity: str, environment: str = "cloud") -> str:
    return (
        f"Remediation context:\n"
        f"Finding: {finding[:300]} | Severity: {severity} | Environment: {environment}\n\n"
        f"Generate steps for:\n"
        f"1. IMMEDIATE (0-1h): Containment\n"
        f"2. SHORT-TERM (24-72h): Root cause fix\n"
        f"3. DETECTION: New SIEM/EDR rules\n"
        f"4. PREVENTIVE: Long-term controls"
    )


def _update_alert_triage(
    alert_id: str,
    verdict: str,
    severity: str,
    confidence: float,
    summary: str,
    mitre_techniques: list = None,
    recommended_actions: list = None,
) -> str:
    triage_result = {
        "verdict": verdict,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "mitre_techniques": mitre_techniques or [],
        "recommended_actions": recommended_actions or [],
        "triaged_at": datetime.now(timezone.utc).isoformat(),
        "agent_version": "v0.2",
    }
    new_status = "closed" if verdict in ("false_positive", "benign") else "in_progress"
    if verdict == "true_positive" and severity in ("CRITICAL", "HIGH"):
        new_status = "open"

    _sb.table("alerts").update({
        "triage_verdict": verdict,
        "triage_confidence": confidence,
        "triage_summary": summary,
        "triage_result": triage_result,
        "status": new_status,
    }).eq("id", alert_id).execute()

    _sb.table("agent_actions").insert({
        "alert_id": alert_id,
        "agent_name": "triage",
        "action_type": "triage",
        "output": triage_result,
        "confidence": confidence,
        "model": "claude-sonnet-4-6",
    }).execute()

    return (
        f"Alert {alert_id} updated.\n"
        f"Verdict: {verdict} | Severity: {severity} | Confidence: {confidence:.0%}\n"
        f"Status -> {new_status}"
    )


def _create_ticket(
    alert_id: str,
    tenant_id: str,
    summary: str,
    priority: str,
    description: str = "",
) -> str:
    result = _sb.table("tickets").insert({
        "tenant_id": tenant_id,
        "alert_id": alert_id,
        "summary": summary,
        "priority": priority,
        "status": "open",
    }).execute()
    ticket_id = result.data[0]["id"] if result.data else "unknown"
    return f"Ticket {ticket_id} created | Priority: {priority} | {summary}"


def _escalate_incident(
    incident_summary: str,
    severity: str,
    reason_for_escalation: str,
    alert_id: str = None,
) -> str:
    record = {
        "escalated": True,
        "alert_id": alert_id,
        "summary": incident_summary,
        "severity": severity,
        "reason": reason_for_escalation,
        "escalated_at": datetime.now(timezone.utc).isoformat(),
    }
    print(f"\n🚨 ESCALATION [{severity}]: {incident_summary[:80]}")
    print(f"   Reason: {reason_for_escalation}")
    if alert_id:
        try:
            _sb.table("alerts").update({"status": "open"}).eq("id", alert_id).execute()
            _sb.table("agent_actions").insert({
                "alert_id": alert_id,
                "agent_name": "triage",
                "action_type": "escalate",
                "output": record,
                "model": "claude-sonnet-4-6",
            }).execute()
        except Exception:
            pass
    return f"Escalated. Severity: {severity}. Status: PENDING_ANALYST_REVIEW."


def _recall_attack_path(
    entity_type: str,
    entity_value: str,
    tenant_id: str,
    max_hops: int = 2,
) -> str:
    """Query the temporal knowledge graph for an entity's attack path."""
    try:
        from memory.graph_memory import GraphMemory
        gm = GraphMemory(tenant_id=tenant_id)
        edges = gm.query_attack_path(entity_type, entity_value, max_hops=max_hops)
        return gm.format_for_agent(edges)
    except Exception as e:
        return f"Knowledge graph query failed: {e}"
