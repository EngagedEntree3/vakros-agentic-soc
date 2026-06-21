"""
Vakros Threat Hunting Agent
-----------------------------
Proactive, hypothesis-driven hunting across Supabase alert data.
Not reactive triage — this agent LOOKS for patterns before they become incidents.

Hunt hypotheses (built-in):
  1. ioc_spread       — same IP/hash seen across multiple hosts
  2. lateral_movement — sequential logins/access across different internal hosts
  3. ttp_cluster      — burst of same MITRE technique in short window
  4. credential_access — multiple credential-related events on one host
  5. beaconing        — repeated low-severity C2-pattern alerts at regular intervals
  6. custom           — analyst-supplied natural language hypothesis

Usage:
  from agent.hunt_agent import run_hunt_agent
  result = run_hunt_agent(hypothesis="lateral_movement", lookback_hours=24)

  # Or custom hypothesis:
  result = run_hunt_agent(
      hypothesis="custom",
      custom_query="Look for signs of insider threat in finance workstations over last 7 days"
  )
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any

import anthropic
from supabase import create_client, Client

log = logging.getLogger("vakros.hunt")

SUPABASE_URL         = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
ANTHROPIC_API_KEY    = os.environ["ANTHROPIC_API_KEY"]
TENANT_ID            = os.environ.get("TENANT_ID", "a080a5df-2ae8-4f3e-a49f-abe69a05d60b")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
ai_client         = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

MAX_ITER = 10
MODEL    = "claude-sonnet-4-6"

# ── Hunt Tool Definitions ──────────────────────────────────────────────────────

HUNT_TOOLS = [
    {
        "name": "query_alerts",
        "description": "Query alerts from Supabase with flexible filters. Returns up to 200 matching alerts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filters": {
                    "type": "object",
                    "description": "Key-value pairs to filter alerts. Supported: event_type, status, severity_gte (int), severity_lte (int), agent_id, triage_verdict, hours_back (int, default 24)",
                },
                "select_fields": {"type": "array", "items": {"type": "string"}, "description": "Fields to return. Default: all."},
                "limit": {"type": "integer", "default": 100},
            },
            "required": [],
        },
    },
    {
        "name": "correlate_ioc",
        "description": "Look up a specific IOC (IP, domain, hash, URL) across all alerts and ioc_cache entries. Returns all alerts where that IOC appears in threat_intel.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_value": {"type": "string", "description": "The IOC to search for"},
                "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "url", "any"]},
            },
            "required": ["ioc_value"],
        },
    },
    {
        "name": "find_host_timeline",
        "description": "Get a chronological timeline of all alerts for a specific host/agent over a time window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "hours_back": {"type": "integer", "default": 48},
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "find_ttp_pattern",
        "description": "Find alerts matching specific MITRE ATT&CK technique IDs across hosts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_ids": {"type": "array", "items": {"type": "string"}, "description": "e.g. ['T1078', 'T1110']"},
                "hours_back": {"type": "integer", "default": 72},
                "min_host_count": {"type": "integer", "default": 1, "description": "Only return if seen on >= N hosts"},
            },
            "required": ["technique_ids"],
        },
    },
    {
        "name": "find_lateral_movement",
        "description": "Detect lateral movement by finding the same user/credential activity across multiple different hosts in sequence.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours_back": {"type": "integer", "default": 48},
                "min_hop_count": {"type": "integer", "default": 2, "description": "Minimum number of distinct hosts in the chain"},
            },
            "required": [],
        },
    },
    {
        "name": "detect_beaconing",
        "description": "Find agents producing regular, periodic low-severity alerts that may indicate C2 beaconing behaviour.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours_back": {"type": "integer", "default": 24},
                "min_repeat": {"type": "integer", "default": 5, "description": "Minimum number of same-rule repeats to flag"},
            },
            "required": [],
        },
    },
    {
        "name": "write_hunt_finding",
        "description": "Record a confirmed hunt finding to the database. Call this when you've found evidence of a threat pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title":          {"type": "string"},
                "hypothesis":     {"type": "string"},
                "severity":       {"type": "integer", "minimum": 1, "maximum": 15},
                "confidence":     {"type": "number", "minimum": 0, "maximum": 1},
                "summary":        {"type": "string"},
                "affected_hosts": {"type": "array", "items": {"type": "string"}},
                "alert_ids":      {"type": "array", "items": {"type": "string"}},
                "mitre_techniques": {"type": "array", "items": {"type": "string"}},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["title", "hypothesis", "severity", "confidence", "summary"],
        },
    },
]

# ── Tool Implementations ───────────────────────────────────────────────────────

def _query_alerts(filters: dict, select_fields: list | None = None, limit: int = 100) -> list[dict]:
    hours_back = int(filters.pop("hours_back", 24))
    since      = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    sev_gte    = filters.pop("severity_gte", None)
    sev_lte    = filters.pop("severity_lte", None)

    fields = ",".join(select_fields) if select_fields else "*"
    q = supabase.from_("alerts").select(fields).eq("tenant_id", TENANT_ID).gte("occurred_at", since).limit(limit)

    for k, v in filters.items():
        q = q.eq(k, v)
    if sev_gte is not None:
        q = q.gte("severity", sev_gte)
    if sev_lte is not None:
        q = q.lte("severity", sev_lte)

    return (q.order("occurred_at", desc=True).execute().data or [])


def _correlate_ioc(ioc_value: str, ioc_type: str = "any") -> dict:
    # Search in threat_intel JSON column (Postgres ILIKE on text cast)
    res = supabase.from_("alerts").select(
        "id, agent_id, rule_desc, severity, occurred_at, threat_intel, triage_verdict"
    ).eq("tenant_id", TENANT_ID).ilike("threat_intel::text", f"%{ioc_value}%").execute()

    cache_res = supabase.from_("ioc_cache").select("*").eq("ioc_value", ioc_value).execute()

    return {
        "alerts_matching": res.data or [],
        "ioc_cache_entry": cache_res.data[0] if cache_res.data else None,
        "host_count":      len(set(a["agent_id"] for a in (res.data or []))),
    }


def _find_host_timeline(agent_id: str, hours_back: int = 48) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    return (
        supabase.from_("alerts").select(
            "id, rule_desc, severity, occurred_at, event_type, triage_verdict, threat_intel"
        ).eq("tenant_id", TENANT_ID).eq("agent_id", agent_id)
        .gte("occurred_at", since).order("occurred_at").execute().data or []
    )


def _find_ttp_pattern(technique_ids: list[str], hours_back: int = 72, min_host_count: int = 1) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    results = []
    for tid in technique_ids:
        res = supabase.from_("alerts").select(
            "id, agent_id, rule_desc, severity, occurred_at, threat_intel"
        ).eq("tenant_id", TENANT_ID).gte("occurred_at", since).ilike("threat_intel::text", f"%{tid}%").execute()
        if res.data:
            results.extend(res.data)

    hosts = list(set(r["agent_id"] for r in results))
    return {
        "matching_alerts": results,
        "affected_hosts":  hosts,
        "host_count":      len(hosts),
        "alert_count":     len(results),
        "meets_threshold": len(hosts) >= min_host_count,
    }


def _find_lateral_movement(hours_back: int = 48, min_hop_count: int = 2) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    lm_types = ["lateral_movement", "authentication_failed", "authentication_success",
                "privilege_escalation", "remote_service"]

    rows: list[dict] = []
    for et in lm_types:
        res = supabase.from_("alerts").select(
            "id, agent_id, rule_desc, severity, occurred_at, event_type, threat_intel"
        ).eq("tenant_id", TENANT_ID).eq("event_type", et).gte("occurred_at", since)\
         .order("occurred_at").execute()
        rows.extend(res.data or [])

    # Group by rough time windows to find chains
    chains: list[dict] = []
    seen_hosts: list[str] = []
    for r in sorted(rows, key=lambda x: x["occurred_at"]):
        if r["agent_id"] not in seen_hosts:
            seen_hosts.append(r["agent_id"])

    return {
        "suspicious_alerts": rows,
        "distinct_hosts":    seen_hosts,
        "hop_count":         len(seen_hosts),
        "possible_movement": len(seen_hosts) >= min_hop_count,
        "alert_count":       len(rows),
    }


def _detect_beaconing(hours_back: int = 24, min_repeat: int = 5) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    res = supabase.from_("alerts").select(
        "agent_id, rule_id, rule_desc, severity"
    ).eq("tenant_id", TENANT_ID).gte("occurred_at", since).execute()

    counts: dict[str, int] = {}
    for r in (res.data or []):
        key = f"{r['agent_id']}::{r['rule_id']}"
        counts[key] = counts.get(key, 0) + 1

    beacons = [
        {"agent_rule": k, "count": v}
        for k, v in counts.items()
        if v >= min_repeat
    ]
    return {"potential_beacons": sorted(beacons, key=lambda x: -x["count"]), "total_flagged": len(beacons)}


def _write_hunt_finding(finding: dict) -> dict:
    """Write finding to agent_actions and optionally create a high-severity alert."""
    record = {
        "alert_id":    None,
        "action_type": "hunt_finding",
        "action_data": {
            **finding,
            "hunted_at": datetime.now(timezone.utc).isoformat(),
        },
        "performed_by": "hunt-agent",
    }
    res = supabase.from_("agent_actions").insert(record).execute()

    # If high-confidence high-severity, also create a synthetic alert
    if finding.get("severity", 0) >= 10 and finding.get("confidence", 0) >= 0.7:
        synth = {
            "tenant_id":    TENANT_ID,
            "wazuh_alert_id": f"hunt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "agent_id":     ", ".join(finding.get("affected_hosts", [])[:3]),
            "rule_desc":    f"[HUNT] {finding['title']}",
            "severity":     finding["severity"],
            "occurred_at":  datetime.now(timezone.utc).isoformat(),
            "status":       "open",
            "source_platform": "hunt_agent",
            "event_type":   "threat_hunt_finding",
            "triage_verdict":  "true_positive",
            "triage_confidence": finding.get("confidence"),
            "triage_summary": finding.get("summary"),
            "triage_result": {
                "mitre_techniques": finding.get("mitre_techniques", []),
                "recommended_actions": finding.get("recommended_actions", []),
                "source_alert_ids": finding.get("alert_ids", []),
            },
        }
        supabase.from_("alerts").insert(synth).execute()

    return {"saved": True, "finding_id": res.data[0]["id"] if res.data else None}


def process_tool_call(name: str, inputs: dict) -> Any:
    if name == "query_alerts":
        return _query_alerts(inputs.get("filters", {}), inputs.get("select_fields"), inputs.get("limit", 100))
    elif name == "correlate_ioc":
        return _correlate_ioc(inputs["ioc_value"], inputs.get("ioc_type", "any"))
    elif name == "find_host_timeline":
        return _find_host_timeline(inputs["agent_id"], inputs.get("hours_back", 48))
    elif name == "find_ttp_pattern":
        return _find_ttp_pattern(inputs["technique_ids"], inputs.get("hours_back", 72), inputs.get("min_host_count", 1))
    elif name == "find_lateral_movement":
        return _find_lateral_movement(inputs.get("hours_back", 48), inputs.get("min_hop_count", 2))
    elif name == "detect_beaconing":
        return _detect_beaconing(inputs.get("hours_back", 24), inputs.get("min_repeat", 5))
    elif name == "write_hunt_finding":
        return _write_hunt_finding(inputs)
    else:
        return {"error": f"Unknown tool: {name}"}


# ── Hunt Agent Loop ────────────────────────────────────────────────────────────

HYPOTHESIS_PROMPTS = {
    "ioc_spread": "Hunt for IOC spread: find IP addresses, file hashes, or domains that appear in alerts across multiple different hosts. If any IOC appears on 2+ distinct hosts, that's a finding.",
    "lateral_movement": "Hunt for lateral movement: look for sequential authentication, remote access, or privilege escalation events that move across different internal hosts in a time-correlated chain.",
    "ttp_cluster": "Hunt for TTP clustering: find any MITRE ATT&CK technique IDs that appear in multiple alerts across different hosts within a short window. A burst of the same TTP = coordinated attack.",
    "credential_access": "Hunt for credential access: look for T1003, T1078, T1110 patterns — credential dumping, valid account abuse, brute force — especially if multiple types occur on the same host.",
    "beaconing": "Hunt for C2 beaconing: find any host producing the exact same alert rule repeatedly at regular intervals (5+ times in 24h). This pattern indicates automated C2 check-ins.",
    "insider_threat": "Hunt for insider threat indicators: look for unusual access patterns on user workstations — after-hours logins, access to unusual systems, large data movements, policy violations.",
}


def run_hunt_agent(
    hypothesis: str = "lateral_movement",
    lookback_hours: int = 24,
    custom_query: str | None = None,
) -> dict:
    """
    Run the threat hunting agent.

    Args:
        hypothesis: One of the built-in hypotheses or 'custom'
        lookback_hours: How far back to look (default 24h)
        custom_query: Free-text hunt query when hypothesis='custom'

    Returns:
        dict with keys: hypothesis, findings, tool_calls_made, iterations
    """
    if hypothesis == "custom" and not custom_query:
        raise ValueError("custom_query required when hypothesis='custom'")

    hunt_instruction = custom_query if hypothesis == "custom" else HYPOTHESIS_PROMPTS.get(
        hypothesis, HYPOTHESIS_PROMPTS["lateral_movement"]
    )

    system_prompt = f"""You are Vakros threat hunter — an elite SOC analyst who proactively hunts for adversary activity in telemetry data.

Your job is NOT reactive triage. You are hunting for patterns that individually look benign but collectively reveal an attack.

Hunting mindset:
- Assume compromise, look for evidence
- Think like an attacker: what MITRE technique chains would lead to the goal?
- Correlate across hosts and time — single-host events are less interesting than multi-host patterns
- Low-severity + high-frequency can be as dangerous as a single critical alert

Lookback window: {lookback_hours} hours.
Current time: {datetime.now(timezone.utc).isoformat()}

When you find evidence, call write_hunt_finding. If you find nothing, explain what you checked and why the environment appears clean.
Be specific — reference actual alert IDs, host names, timestamps."""

    user_msg = f"Hunt hypothesis: {hunt_instruction}\n\nBegin hunting. Use the tools to query data and build your case."

    messages: list[dict] = [{"role": "user", "content": user_msg}]
    findings: list[dict] = []
    tool_calls_made = 0
    iterations = 0

    while iterations < MAX_ITER:
        iterations += 1
        response = ai_client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            tools=HUNT_TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            break

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                tool_calls_made += 1
                log.info(f"[hunt] {block.name}({json.dumps(block.input)[:80]}…)")
                result = process_tool_call(block.name, block.input)

                if block.name == "write_hunt_finding":
                    findings.append({**block.input, "db_result": result})

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result)[:8000],  # truncate large payloads
                })

            messages.append({"role": "user", "content": tool_results})

    # Extract final text summary
    final_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            final_text = block.text
            break

    return {
        "hypothesis":       hypothesis,
        "lookback_hours":   lookback_hours,
        "findings":         findings,
        "findings_count":   len(findings),
        "tool_calls_made":  tool_calls_made,
        "iterations":       iterations,
        "summary":          final_text,
        "hunted_at":        datetime.now(timezone.utc).isoformat(),
    }
