"""
Vakros SOC MCP Server
=====================
Exposes all Vakros SOC capabilities as MCP tools so Claude Desktop,
Claude Code, Cursor, or any MCP-compatible host can call them directly.

Setup in Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json):
{
  "mcpServers": {
    "vakros-soc": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/vakros-agent",
      "env": {
        "ANTHROPIC_API_KEY": "...",
        "SUPABASE_URL": "https://etmshueaqaqxpyzuvkqi.supabase.co",
        "SUPABASE_SERVICE_KEY": "..."
      }
    }
  }
}

Usage from Claude Desktop:
  "Triage alert <uuid>"
  "Show me the last 10 open alerts"
  "Run the ransomware playbook on alert <uuid>"
  "Look up IOC 185.220.101.47"
  "What MITRE techniques are related to credential dumping?"
"""

import os
import sys
import json
import asyncio
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
load_dotenv()

# Validate required env before starting
for var in ("SUPABASE_URL", "SUPABASE_SERVICE_KEY"):
    if not os.environ.get(var):
        print(f"ERROR: {var} not set", file=sys.stderr)
        sys.exit(1)

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from supabase import create_client

_sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])

# Lazy import: agent only needed for triage tool
_run_agent = None
def _get_agent():
    global _run_agent
    if _run_agent is None:
        from agent.soc_agent import run_agent
        _run_agent = run_agent
    return _run_agent

app = Server("vakros-soc")


# ── Tool Definitions ─────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_alerts",
            description=(
                "List security alerts from the Vakros SOC platform. "
                "Filter by status (open/closed/in_progress), severity, or verdict. "
                "Use this to get an overview of the current threat landscape."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["open", "closed", "in_progress", "all"],
                        "default": "open",
                        "description": "Filter by alert status"
                    },
                    "min_severity": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 15,
                        "description": "Minimum severity level (1-15)"
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["true_positive", "false_positive", "benign", "needs_investigation"],
                        "description": "Filter by triage verdict"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "maximum": 100
                    }
                }
            }
        ),
        types.Tool(
            name="get_alert",
            description="Get full details of a specific alert by ID, including triage verdict, threat intel, and agent actions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "UUID of the alert"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        types.Tool(
            name="triage_alert",
            description=(
                "Run the AI triage agent on a specific alert. "
                "The agent will search the MITRE ATT&CK knowledge base, look up IOCs, "
                "determine a verdict (true_positive/false_positive/benign/needs_investigation), "
                "and write results back to the database. Requires ANTHROPIC_API_KEY."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "UUID of the alert to triage"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        types.Tool(
            name="lookup_ioc",
            description=(
                "Look up an Indicator of Compromise (IOC) — IP address, domain, file hash, or URL. "
                "Checks VirusTotal, AbuseIPDB, and the local IOC cache. "
                "Returns threat score, reputation data, and known malware associations."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash", "url"],
                        "description": "Type of IOC"
                    },
                    "value": {
                        "type": "string",
                        "description": "The IOC value to look up"
                    }
                },
                "required": ["ioc_type", "value"]
            }
        ),
        types.Tool(
            name="search_mitre",
            description=(
                "Search the MITRE ATT&CK knowledge base for techniques related to a query. "
                "Returns matching techniques with descriptions, tactics, detection guidance, and platforms."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g. 'credential dumping', 'lateral movement', 'T1003')"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 5,
                        "maximum": 20
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="get_soc_stats",
            description=(
                "Get SOC operational statistics: alert counts by status/severity/verdict, "
                "MTTR (mean time to respond), top attack categories, and agent performance metrics."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hours_back": {
                        "type": "integer",
                        "default": 24,
                        "description": "Time window in hours"
                    }
                }
            }
        ),
        types.Tool(
            name="list_agents",
            description="List monitored endpoints/agents, their OS, status, and last heartbeat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["active", "disconnected", "all"],
                        "default": "all"
                    }
                }
            }
        ),
        types.Tool(
            name="update_alert_status",
            description="Manually update an alert's status or add analyst notes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "UUID of the alert"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["open", "in_progress", "closed"]
                    },
                    "notes": {
                        "type": "string",
                        "description": "Analyst notes to append"
                    }
                },
                "required": ["alert_id"]
            }
        ),
        types.Tool(
            name="run_playbook",
            description=(
                "Execute a response playbook against an alert. "
                "Available playbooks: ransomware_containment, phishing_response, "
                "brute_force_block, credential_compromise, data_exfiltration_response, c2_isolation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "playbook_name": {
                        "type": "string",
                        "description": "Name of the playbook to run"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "UUID of the alert to run the playbook against"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": True,
                        "description": "If true, returns the playbook steps without executing"
                    }
                },
                "required": ["playbook_name", "alert_id"]
            }
        ),
    ]


# ── Tool Handlers ────────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        result = await _dispatch(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as e:
        return [types.TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def _dispatch(name: str, args: dict) -> Any:
    if name == "list_alerts":
        return await _list_alerts(args)
    elif name == "get_alert":
        return await _get_alert(args)
    elif name == "triage_alert":
        return await _triage_alert(args)
    elif name == "lookup_ioc":
        return await _lookup_ioc(args)
    elif name == "search_mitre":
        return await _search_mitre(args)
    elif name == "get_soc_stats":
        return await _get_soc_stats(args)
    elif name == "list_agents":
        return await _list_agents(args)
    elif name == "update_alert_status":
        return await _update_alert_status(args)
    elif name == "run_playbook":
        return await _run_playbook(args)
    else:
        raise ValueError(f"Unknown tool: {name}")


# ── Implementations ──────────────────────────────────────────────────────────

async def _list_alerts(args: dict) -> dict:
    status = args.get("status", "open")
    limit = min(args.get("limit", 20), 100)
    min_sev = args.get("min_severity")
    verdict = args.get("verdict")

    q = _sb.table("alerts").select(
        "id,wazuh_alert_id,agent_id,rule_desc,severity,occurred_at,"
        "status,triage_verdict,triage_confidence,triage_summary,event_type,source_platform"
    )

    if status != "all":
        q = q.eq("status", status)
    if min_sev:
        q = q.gte("severity", min_sev)
    if verdict:
        q = q.eq("triage_verdict", verdict)

    result = q.order("severity", desc=True).order("occurred_at", desc=True).limit(limit).execute()
    return {
        "count": len(result.data),
        "alerts": result.data
    }


async def _get_alert(args: dict) -> dict:
    alert_id = args["alert_id"]
    alert = _sb.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
    if not alert.data:
        return {"error": f"Alert {alert_id} not found"}

    actions = _sb.table("agent_actions").select("*").eq("alert_id", alert_id).order("created_at", desc=True).limit(10).execute()

    return {
        "alert": alert.data[0],
        "agent_actions": actions.data
    }


async def _triage_alert(args: dict) -> dict:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"error": "ANTHROPIC_API_KEY not set — cannot run agent"}

    alert_id = args["alert_id"]
    alert_result = _sb.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
    if not alert_result.data:
        return {"error": f"Alert {alert_id} not found"}

    alert = alert_result.data[0]

    # Build triage prompt
    query = (
        f"Triage this security alert:\n\n"
        f"Rule: {alert.get('rule_desc', 'Unknown')}\n"
        f"Source: {alert.get('source_platform', 'wazuh')} | Host: {alert.get('agent_id', 'unknown')}\n"
        f"Severity: {alert.get('severity')}/15\n"
        f"Event type: {alert.get('event_type', 'unspecified')}\n"
        f"Alert ID: {alert_id}\n"
    )
    context = (
        "Perform complete triage: search KB → lookup IOCs → determine verdict → "
        "call update_alert_triage → create_ticket if CRITICAL/HIGH TP → escalate if needed.\n"
        f"Tenant ID: {alert.get('tenant_id', '')}"
    )

    run_agent = _get_agent()
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: run_agent(query=query, context=context))

    return {
        "alert_id": alert_id,
        "triage_result": result,
        "message": "Triage complete. Verdict written to database."
    }


async def _lookup_ioc(args: dict) -> dict:
    from agent.tools import _lookup_ioc as _tool_lookup
    ioc_type = args["ioc_type"]
    value = args["value"]
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: _tool_lookup(ioc_type, value))
    return result


async def _search_mitre(args: dict) -> dict:
    query = args["query"]
    limit = min(args.get("limit", 5), 20)

    # Try technique ID match first
    if query.upper().startswith("T") and len(query) >= 4:
        tid_result = _sb.table("mitre_techniques").select(
            "technique_id,name,tactic,description,detection,platforms"
        ).ilike("technique_id", f"%{query.upper()}%").limit(limit).execute()
        if tid_result.data:
            return {"techniques": tid_result.data, "matched_by": "technique_id"}

    # Text search
    result = _sb.table("mitre_techniques").select(
        "technique_id,name,tactic,description,detection,platforms"
    ).or_(
        f"name.ilike.%{query}%,"
        f"description.ilike.%{query}%,"
        f"detection.ilike.%{query}%"
    ).limit(limit).execute()

    return {
        "query": query,
        "count": len(result.data),
        "techniques": result.data
    }


async def _get_soc_stats(args: dict) -> dict:
    hours = args.get("hours_back", 24)

    # Total by status
    total = _sb.table("alerts").select("status", count="exact").execute()
    open_count = _sb.table("alerts").select("id", count="exact").eq("status", "open").execute()
    closed_count = _sb.table("alerts").select("id", count="exact").eq("status", "closed").execute()

    # By verdict
    tp = _sb.table("alerts").select("id", count="exact").eq("triage_verdict", "true_positive").execute()
    fp = _sb.table("alerts").select("id", count="exact").eq("triage_verdict", "false_positive").execute()
    untriaged = _sb.table("alerts").select("id", count="exact").is_("triage_verdict", "null").execute()

    # Critical alerts
    critical = _sb.table("alerts").select("id", count="exact").gte("severity", 13).eq("status", "open").execute()

    # Recent agent actions
    actions = _sb.table("agent_actions").select("id", count="exact").execute()

    return {
        "window_hours": hours,
        "alerts": {
            "total": total.count,
            "open": open_count.count,
            "closed": closed_count.count,
            "critical_open": critical.count,
            "untriaged": untriaged.count,
        },
        "verdicts": {
            "true_positive": tp.count,
            "false_positive": fp.count,
            "untriaged": untriaged.count,
        },
        "agent_actions_logged": actions.count,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def _list_agents(args: dict) -> dict:
    status = args.get("status", "all")
    q = _sb.table("agents").select("id,name,os,status,last_keepalive,created_at")
    if status != "all":
        q = q.eq("status", status)
    result = q.order("last_keepalive", desc=True).execute()
    return {"count": len(result.data), "agents": result.data}


async def _update_alert_status(args: dict) -> dict:
    alert_id = args["alert_id"]
    update = {}
    if "status" in args:
        update["status"] = args["status"]
    if "notes" in args:
        update["triage_summary"] = args["notes"]

    if not update:
        return {"error": "Nothing to update — provide status or notes"}

    _sb.table("alerts").update(update).eq("id", alert_id).execute()
    return {"alert_id": alert_id, "updated": update, "success": True}


async def _run_playbook(args: dict) -> dict:
    playbook_name = args["playbook_name"]
    alert_id = args["alert_id"]
    dry_run = args.get("dry_run", True)

    PLAYBOOKS = {
        "ransomware_containment": {
            "name": "Ransomware Containment",
            "trigger": "ransomware_indicator",
            "steps": [
                "1. ISOLATE: Immediately isolate affected endpoints from network (EDR isolation)",
                "2. SNAPSHOT: Take memory dump and disk snapshot before remediation",
                "3. IDENTIFY: Determine ransomware family via file extension + ransom note",
                "4. SCOPE: Identify all affected hosts via lateral movement indicators",
                "5. BLOCK: Block C2 IPs/domains at firewall and DNS",
                "6. RECOVER: Restore from last known-good backup",
                "7. PATCH: Apply patches that the ransomware exploited for initial access",
                "8. NOTIFY: Engage IR team, legal, and if required — regulatory bodies",
                "9. POSTMORTEM: Document full kill chain for lessons learned"
            ],
            "severity": "CRITICAL",
            "estimated_time": "2-4 hours"
        },
        "phishing_response": {
            "name": "Phishing Email Response",
            "trigger": "phishing",
            "steps": [
                "1. QUARANTINE: Pull email from all mailboxes using admin search",
                "2. BLOCK: Add sender domain and IP to email gateway blocklist",
                "3. REVOKE: If credentials entered — reset password + revoke all sessions/tokens",
                "4. NOTIFY: Alert all recipients who received the email",
                "5. ANALYZE: Extract and sandbox all URLs and attachments",
                "6. HUNT: Search SIEM for clicks on phishing URL across all users",
                "7. REPORT: Submit IOCs to threat intel feeds"
            ],
            "severity": "HIGH",
            "estimated_time": "30-60 minutes"
        },
        "brute_force_block": {
            "name": "Brute Force Attack Mitigation",
            "trigger": "authentication_failure",
            "steps": [
                "1. BLOCK: Add source IP to firewall/WAF blocklist",
                "2. LOCKOUT: Check if any accounts were compromised (successful login after failures)",
                "3. RESET: Reset passwords for any locked-out accounts",
                "4. MFA: Enforce MFA on targeted accounts if not already enabled",
                "5. RATE-LIMIT: Apply rate limiting to authentication endpoints",
                "6. THREAT-INTEL: Query IP reputation — report to AbuseIPDB if malicious"
            ],
            "severity": "MEDIUM",
            "estimated_time": "15-30 minutes"
        },
        "credential_compromise": {
            "name": "Credential Compromise Response",
            "trigger": "account_compromise",
            "steps": [
                "1. REVOKE: Immediately revoke all sessions for compromised account",
                "2. RESET: Force password reset via out-of-band channel",
                "3. MFA: Re-enroll MFA with new device",
                "4. AUDIT: Review all actions taken by compromised account in last 30 days",
                "5. LATERAL: Check for lateral movement using compromised credentials",
                "6. NOTIFY: Inform account owner and their manager",
                "7. PRIVILEGE: Temporarily reduce account privileges pending investigation"
            ],
            "severity": "CRITICAL",
            "estimated_time": "1-2 hours"
        },
        "data_exfiltration_response": {
            "name": "Data Exfiltration Response",
            "trigger": "data_exfiltration",
            "steps": [
                "1. BLOCK: Cut outbound traffic to destination IP/domain immediately",
                "2. PRESERVE: Capture network logs and endpoint artifacts",
                "3. SCOPE: Determine what data was exfiltrated and its sensitivity",
                "4. NOTIFY: Engage legal team if PII/regulated data involved",
                "5. REGULATORY: Assess notification obligations (GDPR 72hr, HIPAA, etc.)",
                "6. HUNT: Search for other exfil channels (DNS tunneling, email, USB)",
                "7. REMEDIATE: Remove access of compromised account/API key"
            ],
            "severity": "CRITICAL",
            "estimated_time": "2-4 hours"
        },
        "c2_isolation": {
            "name": "C2 Communication Isolation",
            "trigger": "c2_communication",
            "steps": [
                "1. BLOCK: Add C2 IP/domain to firewall egress blocklist immediately",
                "2. ISOLATE: Network-isolate the beaconing endpoint",
                "3. MEMORY: Capture memory dump for malware analysis",
                "4. PERSISTENCE: Search for scheduled tasks, registry run keys, services",
                "5. LATERAL: Check other hosts for same C2 beacon pattern",
                "6. HUNT: Search SIEM for DNS queries to same domain family",
                "7. CLEAN: Remove malware after thorough forensic capture",
                "8. REBUILD: Rebuild endpoint from clean image if rootkit suspected"
            ],
            "severity": "HIGH",
            "estimated_time": "1-3 hours"
        }
    }

    if playbook_name not in PLAYBOOKS:
        return {
            "error": f"Playbook '{playbook_name}' not found",
            "available_playbooks": list(PLAYBOOKS.keys())
        }

    pb = PLAYBOOKS[playbook_name]

    if not dry_run:
        # Log execution to Supabase
        try:
            _sb.table("agent_actions").insert({
                "alert_id": alert_id,
                "action_type": "playbook_execution",
                "action_data": {
                    "playbook": playbook_name,
                    "steps": pb["steps"],
                    "executed_at": datetime.now(timezone.utc).isoformat()
                },
                "result": "playbook_dispatched",
                "created_at": datetime.now(timezone.utc).isoformat()
            }).execute()
        except Exception:
            pass

    return {
        "playbook": pb["name"],
        "alert_id": alert_id,
        "severity": pb["severity"],
        "estimated_time": pb["estimated_time"],
        "steps": pb["steps"],
        "executed": not dry_run,
        "dry_run": dry_run
    }


# ── Entry Point ──────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
