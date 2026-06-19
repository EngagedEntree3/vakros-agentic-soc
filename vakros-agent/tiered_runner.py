"""
Vakros Tiered Triage Runner
============================
Runs SOC1 (fast) on all open alerts, then automatically escalates
CRITICAL/HIGH true positives to SOC2 (deep investigation).

Inspired by SamiGPT's SOC1/SOC2 tier architecture (BlackHat 2025).

Usage:
    python tiered_runner.py                  # Process all open alerts
    python tiered_runner.py --soc2-only      # Only run SOC2 on already-escalated alerts
    python tiered_runner.py --limit 10       # Cap at 10 alerts
    python tiered_runner.py --dry-run        # No agent calls, just show what would run
    python tiered_runner.py --alert-id <uuid>  # Single alert

Flow:
    1. SOC1 triages all alerts (fast, claude-haiku, max 4 iterations)
    2. CRITICAL/HIGH true positives → SOC2 deep investigation (sonnet, max 12 iterations)
    3. Results written to DB in real time
    4. Summary printed at end
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime, timezone

from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

for var in ("ANTHROPIC_API_KEY", "SUPABASE_URL", "SUPABASE_SERVICE_KEY"):
    if not os.environ.get(var):
        print(f"ERROR: Missing {var}")
        sys.exit(1)

from agent.soc1_agent import run_soc1_agent
from agent.soc2_agent import run_soc2_agent

_sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])


def fetch_open_alerts(limit: int = 50) -> list[dict]:
    result = _sb.table("alerts") \
        .select("*") \
        .eq("status", "open") \
        .is_("triage_verdict", "null") \
        .order("severity", desc=True) \
        .order("occurred_at", desc=True) \
        .limit(limit) \
        .execute()
    return result.data or []


def fetch_escalated_alerts(limit: int = 20) -> list[dict]:
    """Fetch alerts that SOC1 flagged for SOC2 escalation."""
    result = _sb.table("alerts") \
        .select("*") \
        .eq("status", "open") \
        .eq("triage_verdict", "true_positive") \
        .gte("severity", 11) \
        .order("severity", desc=True) \
        .limit(limit) \
        .execute()
    return result.data or []


def run_tiered_batch(
    alert_id: str | None = None,
    limit: int = 50,
    dry_run: bool = False,
    soc2_only: bool = False,
):
    start = time.time()
    now = datetime.now(timezone.utc).isoformat()

    print(f"\nVakros Tiered Triage  |  {now}")
    print(f"Mode: {'SOC2-ONLY' if soc2_only else 'SOC1 → SOC2'}{' (DRY RUN)' if dry_run else ''}")
    print("=" * 60)

    # ── SOC2-only mode ──────────────────────────────────────────
    if soc2_only:
        alerts = fetch_escalated_alerts(limit)
        if not alerts:
            print("No escalated alerts awaiting SOC2.")
            return
        print(f"SOC2 investigating {len(alerts)} escalated alert(s)...")
        soc2_results = []
        for i, alert in enumerate(alerts, 1):
            print(f"\n[SOC2 {i}/{len(alerts)}] {alert.get('rule_desc', 'Unknown')[:60]}")
            if dry_run:
                print("  [DRY RUN] Skipping.")
                continue
            t0 = time.time()
            r = run_soc2_agent(alert)
            print(f"  ✓ {r['verdict']} | {r['severity']} | {r['confidence']:.0%} | {r['iterations']} iters | {time.time()-t0:.1f}s")
            soc2_results.append(r)
        _print_summary([], soc2_results, time.time() - start)
        return

    # ── Normal mode: SOC1 then SOC2 ─────────────────────────────
    if alert_id:
        result = _sb.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
        alerts = result.data if result.data else []
        if not alerts:
            print(f"Alert {alert_id} not found.")
            return
    else:
        alerts = fetch_open_alerts(limit)

    if not alerts:
        print("No open untriaged alerts found.")
        return

    print(f"SOC1 processing {len(alerts)} alert(s)...")

    soc1_results = []
    escalate_queue = []

    for i, alert in enumerate(alerts, 1):
        rule = alert.get("rule_desc", "Unknown")[:55]
        sev  = alert.get("severity", 0)
        print(f"\n[SOC1 {i}/{len(alerts)}] [{sev}/15] {rule}")

        if dry_run:
            print("  [DRY RUN] Skipping agent call.")
            soc1_results.append({"alert_id": alert["id"], "skipped": True})
            continue

        t0 = time.time()
        try:
            r = run_soc1_agent(alert)
            elapsed = round(time.time() - t0, 1)
            flag = "→ SOC2" if r.get("escalate_to_soc2") else "✓"
            print(f"  {flag} {r['verdict']} | {r['severity']} | {r['confidence']:.0%} | {r['iterations']} iters | {elapsed}s")
            soc1_results.append(r)

            if r.get("escalate_to_soc2"):
                escalate_queue.append((alert, r))

        except Exception as e:
            print(f"  ERROR: {e}")
            soc1_results.append({"alert_id": alert["id"], "error": str(e)})

        time.sleep(0.3)

    # ── SOC2 escalation ─────────────────────────────────────────
    soc2_results = []
    if escalate_queue:
        print(f"\n{'='*60}")
        print(f"SOC2 investigating {len(escalate_queue)} escalated alert(s)...")

        for i, (alert, soc1_r) in enumerate(escalate_queue, 1):
            rule = alert.get("rule_desc", "Unknown")[:55]
            sev  = alert.get("severity", 0)
            print(f"\n[SOC2 {i}/{len(escalate_queue)}] [{sev}/15] {rule}")

            if dry_run:
                print("  [DRY RUN] Skipping.")
                continue

            t0 = time.time()
            try:
                r = run_soc2_agent(alert, soc1_result=soc1_r)
                elapsed = round(time.time() - t0, 1)
                print(
                    f"  ✓ {r['verdict']} | {r['severity']} | {r['confidence']:.0%} | "
                    f"{r['iterations']} iters | ticket={'YES' if r.get('ticket_created') else 'NO'} | {elapsed}s"
                )
                soc2_results.append(r)
            except Exception as e:
                print(f"  ERROR: {e}")
                soc2_results.append({"alert_id": alert["id"], "error": str(e)})

            time.sleep(0.3)

    _print_summary(soc1_results, soc2_results, time.time() - start)


def _print_summary(soc1: list, soc2: list, elapsed: float):
    print(f"\n{'='*60}")
    print(f"COMPLETE  |  {elapsed:.1f}s total\n")

    if soc1:
        v1 = {}
        for r in soc1:
            v = r.get("verdict", "error" if "error" in r else "skipped")
            v1[v] = v1.get(v, 0) + 1
        print(f"SOC1 ({len(soc1)} alerts): {json.dumps(v1)}")
        errors1 = sum(1 for r in soc1 if "error" in r)
        if errors1:
            print(f"  Errors: {errors1}")

    if soc2:
        v2 = {}
        for r in soc2:
            v = r.get("verdict", "error" if "error" in r else "skipped")
            v2[v] = v2.get(v, 0) + 1
        tickets = sum(1 for r in soc2 if r.get("ticket_created"))
        print(f"SOC2 ({len(soc2)} alerts): {json.dumps(v2)}  |  Tickets: {tickets}")

    avg = elapsed / max(len(soc1) + len(soc2), 1)
    print(f"Avg: {avg:.1f}s/alert")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vakros Tiered Triage Runner")
    parser.add_argument("--alert-id", help="Single alert UUID")
    parser.add_argument("--limit",    type=int, default=50)
    parser.add_argument("--dry-run",  action="store_true")
    parser.add_argument("--soc2-only", action="store_true", help="Run SOC2 on already-escalated alerts")
    args = parser.parse_args()

    run_tiered_batch(
        alert_id=args.alert_id,
        limit=args.limit,
        dry_run=args.dry_run,
        soc2_only=args.soc2_only,
    )
