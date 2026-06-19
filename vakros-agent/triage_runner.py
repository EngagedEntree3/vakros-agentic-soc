"""
Vakros Alert Triage Runner  —  v0.1
====================================
Pulls open/untriaged alerts from Supabase and runs each through the
SOC triage agent. Writes verdicts back to the database in real time.

Usage:
    # Triage all open alerts
    python triage_runner.py

    # Triage a specific alert
    python triage_runner.py --alert-id <uuid>

    # Dry-run (no DB writes)
    python triage_runner.py --dry-run

    # Limit to N alerts
    python triage_runner.py --limit 10

Environment variables required:
    ANTHROPIC_API_KEY
    SUPABASE_URL
    SUPABASE_SERVICE_KEY

Optional:
    VIRUSTOTAL_API_KEY
    ABUSEIPDB_API_KEY
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone

from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# Validate env before importing agent (avoid cryptic errors)
for var in ("ANTHROPIC_API_KEY", "SUPABASE_URL", "SUPABASE_SERVICE_KEY"):
    if not os.environ.get(var):
        print(f"ERROR: Missing required environment variable: {var}")
        sys.exit(1)

from agent.soc_agent import run_agent

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
_sb = create_client(SUPABASE_URL, SUPABASE_KEY)


# ── Alert Fetching ───────────────────────────────────────────────────────────

def fetch_open_alerts(limit: int = 50) -> list[dict]:
    """Fetch alerts that need triage: open status with no verdict yet."""
    result = _sb.table("alerts") \
        .select("*") \
        .eq("status", "open") \
        .is_("triage_verdict", "null") \
        .order("occurred_at", desc=True) \
        .limit(limit) \
        .execute()
    return result.data or []


def fetch_alert_by_id(alert_id: str) -> dict | None:
    result = _sb.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
    return result.data[0] if result.data else None


def fetch_tenant_id(alert: dict) -> str:
    return alert.get("tenant_id", "")


# ── Alert → Agent Query ──────────────────────────────────────────────────────

def build_triage_query(alert: dict) -> tuple[str, str]:
    """
    Build the natural-language triage prompt from a raw alert record.
    Returns (query, context).
    """
    rule_desc   = alert.get("rule_desc", "Unknown alert")
    severity    = alert.get("severity", "N/A")
    agent_id    = alert.get("agent_id", "unknown host")
    occurred_at = alert.get("occurred_at", "unknown time")
    source      = alert.get("source_platform", "wazuh")
    threat_intel = alert.get("threat_intel")
    event_type  = alert.get("event_type", "")

    query = (
        f"Triage this security alert:\n\n"
        f"Rule: {rule_desc}\n"
        f"Source: {source} | Agent/Host: {agent_id}\n"
        f"Severity (raw): {severity}/15\n"
        f"Event type: {event_type or 'not specified'}\n"
        f"Time: {occurred_at}\n"
        f"Alert ID: {alert['id']}\n"
    )

    if threat_intel:
        query += f"\nThreat Intel context: {json.dumps(threat_intel)}\n"

    context = (
        f"Perform a complete triage:\n"
        f"1. Search knowledge base for this alert type and related MITRE techniques\n"
        f"2. Look up any IOCs present in the alert\n"
        f"3. Assess severity using the full alert context\n"
        f"4. Determine verdict: true_positive / false_positive / benign / needs_investigation\n"
        f"5. Call update_alert_triage with your verdict (this writes to the database)\n"
        f"6. If true_positive AND severity is CRITICAL or HIGH: also call create_ticket\n"
        f"7. If CRITICAL severity or confidence < 0.6: call escalate_incident\n\n"
        f"Tenant ID for ticket creation: {fetch_tenant_id(alert)}"
    )

    return query, context


# ── Main Runner ──────────────────────────────────────────────────────────────

def triage_alert(alert: dict, dry_run: bool = False) -> dict:
    alert_id   = alert["id"]
    rule_desc  = alert.get("rule_desc", "Unknown")
    started_at = time.time()

    print(f"\n{'='*60}")
    print(f"[TRIAGE] {rule_desc}")
    print(f"  ID:       {alert_id}")
    print(f"  Severity: {alert.get('severity')}/15")
    print(f"  Host:     {alert.get('agent_id', 'unknown')}")

    if dry_run:
        print("  [DRY RUN] Skipping agent call.")
        return {"alert_id": alert_id, "skipped": True}

    query, context = build_triage_query(alert)

    try:
        result = run_agent(query=query, context=context)
        elapsed = round(time.time() - started_at, 1)

        verdict    = result.get("verdict") or result.get("triage_verdict", "needs_investigation")
        severity   = result.get("severity", "MEDIUM")
        confidence = result.get("confidence", 0.5)
        summary    = result.get("summary", "No summary generated.")
        escalated  = result.get("escalated", False)

        print(f"  Verdict:    {verdict}")
        print(f"  Severity:   {severity}")
        print(f"  Confidence: {confidence:.0%}")
        print(f"  Escalated:  {escalated}")
        print(f"  Time:       {elapsed}s")
        print(f"  Summary:    {summary[:120]}...")

        return {
            "alert_id":  alert_id,
            "verdict":   verdict,
            "severity":  severity,
            "confidence": confidence,
            "escalated": escalated,
            "elapsed_s": elapsed,
        }

    except Exception as e:
        elapsed = round(time.time() - started_at, 1)
        print(f"  ERROR: {e}")
        # Write a failure record so we don't retry infinitely
        try:
            _sb.table("alerts").update({
                "triage_summary": f"Agent error: {str(e)[:200]}",
                "needs_retriage": True,
                "retriage_count": (alert.get("retriage_count") or 0) + 1,
            }).eq("id", alert_id).execute()
        except Exception:
            pass
        return {"alert_id": alert_id, "error": str(e), "elapsed_s": elapsed}


def run_triage_batch(
    alert_id: str | None = None,
    limit: int = 50,
    dry_run: bool = False,
) -> None:
    start = time.time()

    if alert_id:
        alert = fetch_alert_by_id(alert_id)
        if not alert:
            print(f"Alert {alert_id} not found.")
            return
        alerts = [alert]
    else:
        alerts = fetch_open_alerts(limit=limit)

    if not alerts:
        print("No open untriaged alerts found.")
        return

    print(f"\nVakros Triage Runner  |  {datetime.now(timezone.utc).isoformat()}")
    print(f"Alerts to process: {len(alerts)}{' (DRY RUN)' if dry_run else ''}")

    results = []
    for i, alert in enumerate(alerts, 1):
        print(f"\n[{i}/{len(alerts)}]", end="")
        result = triage_alert(alert, dry_run=dry_run)
        results.append(result)
        # Small delay to avoid API rate limits
        if i < len(alerts):
            time.sleep(0.5)

    # Summary
    total = len(results)
    errors    = sum(1 for r in results if "error" in r)
    skipped   = sum(1 for r in results if r.get("skipped"))
    escalated = sum(1 for r in results if r.get("escalated"))
    verdicts  = {}
    for r in results:
        v = r.get("verdict", "error")
        verdicts[v] = verdicts.get(v, 0) + 1

    elapsed_total = round(time.time() - start, 1)

    print(f"\n{'='*60}")
    print(f"TRIAGE COMPLETE  |  {elapsed_total}s total")
    print(f"  Processed: {total}")
    print(f"  Errors:    {errors}")
    print(f"  Skipped:   {skipped}")
    print(f"  Escalated: {escalated}")
    print(f"  Verdicts:  {json.dumps(verdicts)}")
    print(f"  Avg time:  {elapsed_total/max(total,1):.1f}s/alert")


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vakros Alert Triage Runner")
    parser.add_argument("--alert-id", help="Triage a specific alert by UUID")
    parser.add_argument("--limit",    type=int, default=50, help="Max alerts to process")
    parser.add_argument("--dry-run",  action="store_true", help="Fetch alerts but don't call agent")
    args = parser.parse_args()

    run_triage_batch(
        alert_id=args.alert_id,
        limit=args.limit,
        dry_run=args.dry_run,
    )
