"""
Vakros SOC1 Agent — Fast Triage
================================
Tier 1: Quick classification pass. Goal is < 30 seconds per alert.
Handles the bulk of alerts: FPs, benign, and clear-cut TPs.
Routes CRITICAL/HIGH true positives to SOC2 for deep investigation.

Decision tree:
  LOW severity (1-6)   → FP/benign presumed, confirm with KB search
  MED severity (7-10)  → Quick IOC check + KB lookup → verdict
  HIGH severity (11-12) → Full triage → route to SOC2 if TP
  CRITICAL (13-15)     → Always route to SOC2 after initial triage
"""

import os
import json
from typing import Any

import anthropic

# Reuse tools from the main tools module
from agent.tools import TOOL_DEFINITIONS, process_tool_call

MODEL = "claude-haiku-4-5-20251001"   # Fast + cheap for tier 1
MAX_ITER = 4                            # Hard cap: quick triage only


SOC1_SYSTEM = """You are a Tier 1 SOC analyst at Vakros AI Security Operations. 
Your role is fast, efficient alert triage — classify alerts quickly so the team can focus on real threats.

SPEED IS CRITICAL. You have 4 tool calls maximum.

Decision framework:
- Search knowledge base (1 call max)
- Look up IOCs only if an external IP/hash is present in threat_intel (1 call max)  
- Determine verdict from evidence
- Call update_alert_triage with your verdict (required)

Verdict guide:
- false_positive: Known safe behavior, authorized scan, expected system activity
- benign: Unusual but not threatening; no malicious intent
- true_positive: Confirmed attack or compromise indicator  
- needs_investigation: Ambiguous — escalate to SOC2

After update_alert_triage:
- STOP if verdict is false_positive or benign
- STOP if confidence >= 0.85 on true_positive with severity < 11
- For CRITICAL/HIGH true_positives: recommend SOC2 escalation in summary"""


def run_soc1_agent(alert: dict) -> dict:
    """
    Run SOC1 fast triage on a single alert.
    Returns triage result dict with verdict, severity, confidence, escalate_to_soc2 flag.
    """
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    alert_id   = alert["id"]
    rule_desc  = alert.get("rule_desc", "Unknown alert")
    severity   = alert.get("severity", 0)
    agent_id   = alert.get("agent_id", "unknown")
    event_type = alert.get("event_type", "")
    threat_intel = alert.get("threat_intel", {})

    # Build focused prompt
    prompt = (
        f"ALERT ID: {alert_id}\n"
        f"Rule: {rule_desc}\n"
        f"Host: {agent_id} | Severity: {severity}/15 | Type: {event_type or 'unspecified'}\n"
    )
    if threat_intel:
        prompt += f"Threat Intel: {json.dumps(threat_intel)}\n"

    prompt += (
        f"\nTriage this alert. You have {MAX_ITER} tool calls max.\n"
        f"Required: call update_alert_triage with your verdict.\n"
        f"Tenant: {alert.get('tenant_id', '')}"
    )

    messages = [{"role": "user", "content": prompt}]

    iterations = 0
    result = {
        "alert_id": alert_id,
        "verdict": "needs_investigation",
        "severity": "MEDIUM",
        "confidence": 0.5,
        "summary": "SOC1 triage incomplete",
        "escalate_to_soc2": severity >= 11,
        "iterations": 0,
        "tier": "SOC1"
    }

    while iterations < MAX_ITER:
        iterations += 1
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SOC1_SYSTEM,
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

            # Capture triage result
            if tc.name == "update_alert_triage":
                result.update({
                    "verdict":    tc.input.get("verdict", result["verdict"]),
                    "severity":   tc.input.get("severity", result["severity"]),
                    "confidence": tc.input.get("confidence", result["confidence"]),
                    "summary":    tc.input.get("summary", result["summary"]),
                })
                sev_str = result["severity"]
                verdict = result["verdict"]
                conf    = result["confidence"]
                result["escalate_to_soc2"] = (
                    verdict == "true_positive" and
                    (sev_str in ("CRITICAL", "HIGH") or conf < 0.7)
                )

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": json.dumps(tool_output)
            })

        messages.append({"role": "user", "content": tool_results})

    result["iterations"] = iterations
    return result
