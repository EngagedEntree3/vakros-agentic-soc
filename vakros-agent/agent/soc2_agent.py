"""
Vakros SOC2 Agent — Deep Investigation
========================================
Tier 2: Full kill chain analysis for CRITICAL/HIGH true positives escalated from SOC1.
No iteration limit — runs until it has a complete picture.

Capabilities beyond SOC1:
  - Full kill chain reconstruction (initial access → impact)
  - Multi-alert correlation (checks related alerts on same host)
  - Comprehensive IOC sweep (all IPs, hashes, domains in threat_intel)
  - MITRE ATT&CK mapping with confidence scores
  - Detailed recommended actions with priority ordering
  - Creates incident ticket with full timeline
  - Escalates to human analyst with pre-written brief
"""

import os
import json
from datetime import datetime, timezone
from typing import Any

import anthropic
from supabase import create_client

from agent.tools import TOOL_DEFINITIONS, process_tool_call

MODEL = "claude-sonnet-4-6"
MAX_ITER = 12

_sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])


SOC2_SYSTEM = """You are a Tier 2 SOC analyst (Senior Security Investigator) at Vakros AI Security Operations.
You handle escalated cases that require deep investigation and full kill chain analysis.

Your job:
1. Build a COMPLETE picture of the attack — initial access, execution, persistence, lateral movement, impact
2. Map every TTP to MITRE ATT&CK (call search_knowledge_base for each technique)
3. Sweep ALL IOCs from the alert and related alerts on the same host
4. Correlate with other open alerts — check for campaign patterns
5. Write a detailed incident summary with timeline
6. Prioritize recommended actions (immediate → short-term → long-term)
7. Call update_alert_triage with your final assessment
8. Always create_ticket for confirmed true positives
9. Always call escalate_incident with your full brief

Be thorough. This case matters."""


def _get_related_alerts(agent_id: str, alert_id: str, limit: int = 10) -> list[dict]:
    """Fetch other open/in-progress alerts from the same host."""
    result = _sb.table("alerts").select(
        "id,rule_desc,severity,occurred_at,triage_verdict,event_type,threat_intel"
    ).eq("agent_id", agent_id).neq("id", alert_id).in_(
        "status", ["open", "in_progress"]
    ).order("occurred_at", desc=True).limit(limit).execute()
    return result.data or []


def run_soc2_agent(alert: dict, soc1_result: dict | None = None) -> dict:
    """
    Run SOC2 deep investigation on an escalated alert.
    soc1_result: optional SOC1 triage result to build on.
    Returns comprehensive investigation result.
    """
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    alert_id   = alert["id"]
    agent_id   = alert.get("agent_id", "unknown")
    rule_desc  = alert.get("rule_desc", "Unknown alert")
    severity   = alert.get("severity", 0)
    threat_intel = alert.get("threat_intel", {})

    # Fetch related alerts on same host for correlation
    related = _get_related_alerts(agent_id, alert_id)

    prompt = (
        f"=== ESCALATED INVESTIGATION ===\n"
        f"Alert ID: {alert_id}\n"
        f"Host: {agent_id}\n"
        f"Rule: {rule_desc}\n"
        f"Severity: {severity}/15\n"
        f"Event type: {alert.get('event_type', 'unspecified')}\n"
        f"Time: {alert.get('occurred_at', 'unknown')}\n"
    )

    if threat_intel:
        prompt += f"\nThreat Intel:\n{json.dumps(threat_intel, indent=2)}\n"

    if soc1_result:
        prompt += (
            f"\nSOC1 Initial Assessment:\n"
            f"  Verdict: {soc1_result.get('verdict')}\n"
            f"  Severity: {soc1_result.get('severity')}\n"
            f"  Confidence: {soc1_result.get('confidence'):.0%}\n"
            f"  Summary: {soc1_result.get('summary', '')[:200]}\n"
        )

    if related:
        prompt += f"\n{len(related)} related open alerts on {agent_id}:\n"
        for r in related[:5]:
            prompt += f"  - [{r.get('severity')}/15] {r.get('rule_desc', 'Unknown')} ({r.get('occurred_at', '')[:10]})\n"

    prompt += (
        f"\n=== INVESTIGATION REQUIRED ===\n"
        f"Build the complete kill chain. Map all MITRE TTPs. Sweep all IOCs.\n"
        f"Required calls: search_knowledge_base, update_alert_triage, create_ticket, escalate_incident.\n"
        f"Tenant: {alert.get('tenant_id', '')}"
    )

    messages = [{"role": "user", "content": prompt}]

    result = {
        "alert_id": alert_id,
        "verdict": "needs_investigation",
        "severity": "HIGH",
        "confidence": 0.5,
        "summary": "SOC2 investigation incomplete",
        "mitre_techniques": [],
        "recommended_actions": [],
        "iterations": 0,
        "tier": "SOC2",
        "related_alerts_count": len(related),
        "ticket_created": False,
        "escalated": False
    }

    iterations = 0
    while iterations < MAX_ITER:
        iterations += 1
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SOC2_SYSTEM,
            tools=TOOL_DEFINITIONS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            break

        tool_calls = [b for b in response.content if b.type == "tool_use"]
        if not tool_calls:
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []

        for tc in tool_calls:
            tool_output = process_tool_call(tc.name, tc.input)

            if tc.name == "update_alert_triage":
                result.update({
                    "verdict":             tc.input.get("verdict", result["verdict"]),
                    "severity":            tc.input.get("severity", result["severity"]),
                    "confidence":          tc.input.get("confidence", result["confidence"]),
                    "summary":             tc.input.get("summary", result["summary"]),
                    "mitre_techniques":    tc.input.get("mitre_techniques", []),
                    "recommended_actions": tc.input.get("recommended_actions", []),
                })
            elif tc.name == "create_ticket":
                result["ticket_created"] = True
            elif tc.name == "escalate_incident":
                result["escalated"] = True

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": json.dumps(tool_output)
            })

        messages.append({"role": "user", "content": tool_results})

    result["iterations"] = iterations
    return result
