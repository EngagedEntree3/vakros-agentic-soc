"""
Vakros Wazuh Webhook Ingestion Server
--------------------------------------
FunnyWolf Redis-stream pattern, adapted with asyncio.Queue as the stream buffer.

Flow:
  Wazuh (custom alert script) → POST /webhook/wazuh
    → normalize_wazuh_alert()
    → ALERT_QUEUE.put()           ← producer
    → return 200 immediately

  IngestWorker (background)
    → ALERT_QUEUE.get()           ← consumer
    → deduplicate (ioc_cache / wazuh_alert_id)
    → upsert alerts table
    → auto-trigger SOC1 if severity >= AUTO_TRIAGE_THRESHOLD
    → log ingest_action to agent_actions
"""

import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from supabase import create_client, Client

# ── Config ─────────────────────────────────────────────────────────────────────

SUPABASE_URL         = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
WEBHOOK_SECRET       = os.environ.get("WEBHOOK_SECRET", "")           # optional HMAC secret
TENANT_ID            = os.environ.get("TENANT_ID", "a080a5df-2ae8-4f3e-a49f-abe69a05d60b")
AUTO_TRIAGE_THRESHOLD = int(os.environ.get("AUTO_TRIAGE_THRESHOLD", "7"))  # sev >= 7 auto-triage
QUEUE_MAX_SIZE        = int(os.environ.get("QUEUE_MAX_SIZE", "1000"))
WORKER_CONCURRENCY    = int(os.environ.get("WORKER_CONCURRENCY", "4"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vakros.ingest")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
ALERT_QUEUE: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)

app = FastAPI(title="Vakros Ingest", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST", "GET"])

# ── Normalization ──────────────────────────────────────────────────────────────

WAZUH_LEVEL_MAP = {
    # Wazuh rule levels (0-15) → our severity (1-15), direct passthrough with floor
    range(0, 3):   2,
    range(3, 5):   4,
    range(5, 7):   6,
    range(7, 9):   8,
    range(9, 11):  10,
    range(11, 13): 12,
    range(13, 16): 14,
}

def wazuh_level_to_severity(level: int) -> int:
    for r, sev in WAZUH_LEVEL_MAP.items():
        if level in r:
            return sev
    return min(max(level, 1), 15)


def normalize_wazuh_alert(raw: dict) -> dict:
    """
    Map a Wazuh JSON alert to our alerts schema.
    Wazuh alert structure ref: https://documentation.wazuh.com/current/user-manual/manager/alert-format.html
    """
    rule     = raw.get("rule", {})
    agent    = raw.get("agent", {})
    data     = raw.get("data", {})
    location = raw.get("location", "")

    # Derive wazuh_alert_id — use id field or hash of rule+agent+timestamp
    alert_id = raw.get("id") or raw.get("_id") or hashlib.sha256(
        f"{rule.get('id','')}{agent.get('id','')}{raw.get('timestamp','')}".encode()
    ).hexdigest()[:24]

    severity = wazuh_level_to_severity(int(rule.get("level", 3)))

    # Event type from MITRE tactic or rule groups
    mitre    = rule.get("mitre", {})
    tactics  = mitre.get("tactic", [])
    groups   = rule.get("groups", [])
    event_type = (
        tactics[0].replace(" ", "_").lower() if tactics else
        groups[0].replace(" ", "_").lower() if groups else
        "generic_alert"
    )

    # Threat intel: embed MITRE technique IDs + IOCs from data
    threat_intel: dict[str, Any] = {}
    if mitre.get("id"):
        threat_intel["mitre_techniques"] = mitre["id"] if isinstance(mitre["id"], list) else [mitre["id"]]
    if mitre.get("tactic"):
        threat_intel["mitre_tactics"] = mitre["tactic"] if isinstance(mitre["tactic"], list) else [mitre["tactic"]]

    # Extract network IOCs if present (Wazuh syscheck / network events)
    for ioc_field in ["srcip", "dstip", "src_ip", "dst_ip"]:
        if data.get(ioc_field):
            threat_intel.setdefault("ips", []).append(data[ioc_field])
    for hash_field in ["md5_after", "sha256_after", "hash"]:
        if data.get(hash_field):
            threat_intel["file_hash"] = data[hash_field]
    if data.get("url"):
        threat_intel["url"] = data["url"]

    return {
        "id":              str(uuid.uuid4()),
        "tenant_id":       TENANT_ID,
        "wazuh_alert_id":  alert_id,
        "agent_id":        agent.get("name") or agent.get("id") or "unknown",
        "rule_id":         int(rule.get("id", 0)) if rule.get("id") else None,
        "rule_desc":       rule.get("description") or raw.get("full_log", "")[:255],
        "severity":        severity,
        "occurred_at":     raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "status":          "open",
        "source_platform": "wazuh",
        "event_type":      event_type,
        "threat_intel":    threat_intel if threat_intel else None,
        "raw_event":       raw,
        "triage_verdict":  None,
        "needs_retriage":  False,
    }


# ── Ingest Worker ──────────────────────────────────────────────────────────────

async def ingest_worker(worker_id: int):
    """Drain the queue, upsert to Supabase, optionally trigger SOC1."""
    log.info(f"[worker-{worker_id}] started")
    while True:
        try:
            alert_row = await ALERT_QUEUE.get()
            wazuh_id  = alert_row["wazuh_alert_id"]

            # Deduplication — skip if already in DB
            existing = supabase.from_("alerts").select("id").eq(
                "wazuh_alert_id", wazuh_id
            ).maybe_single().execute()
            if existing.data:
                log.debug(f"[worker-{worker_id}] duplicate {wazuh_id}, skipping")
                ALERT_QUEUE.task_done()
                continue

            # Insert
            result = supabase.from_("alerts").insert(alert_row).execute()
            if result.data:
                inserted = result.data[0]
                log.info(
                    f"[worker-{worker_id}] inserted alert {inserted['id']} "
                    f"sev={inserted['severity']} rule='{inserted['rule_desc'][:60]}'"
                )

                # Auto-trigger SOC1 for high-severity
                if (inserted.get("severity") or 0) >= AUTO_TRIAGE_THRESHOLD:
                    asyncio.create_task(auto_triage(inserted))

        except Exception as e:
            log.error(f"[worker-{worker_id}] error: {e}", exc_info=True)
        finally:
            ALERT_QUEUE.task_done()


async def auto_triage(alert: dict):
    """Fire-and-forget SOC1 triage for qualifying alerts."""
    try:
        log.info(f"[auto-triage] starting SOC1 for alert {alert['id']}")
        # Run in executor so blocking agent code doesn't stall event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_soc1_sync, alert)
        log.info(
            f"[auto-triage] alert {alert['id']} → "
            f"verdict={result.get('verdict')} conf={result.get('confidence')}"
        )
    except Exception as e:
        log.error(f"[auto-triage] failed for {alert['id']}: {e}", exc_info=True)


def _run_soc1_sync(alert: dict) -> dict:
    """Synchronous wrapper called from executor thread."""
    from agent.soc1_agent import run_soc1_agent
    return run_soc1_agent(alert)


# ── App Lifecycle ──────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    for i in range(WORKER_CONCURRENCY):
        asyncio.create_task(ingest_worker(i))
    log.info(f"Vakros ingest server ready — {WORKER_CONCURRENCY} workers, threshold={AUTO_TRIAGE_THRESHOLD}")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "queue_size": ALERT_QUEUE.qsize()}


@app.post("/webhook/wazuh")
async def wazuh_webhook(request: Request, x_wazuh_token: str = Header(default="")):
    """
    Receives Wazuh alerts via custom alert script or integrations module.
    Configure in /var/ossec/etc/ossec.conf:

      <integration>
        <name>custom-vakros</name>
        <hook_url>http://YOUR_SERVER:8001/webhook/wazuh</hook_url>
        <level>3</level>
        <alert_format>json</alert_format>
      </integration>
    """
    # Optional token auth
    if WEBHOOK_SECRET and x_wazuh_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid webhook token")

    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Handle batch (list) or single alert
    alerts = raw if isinstance(raw, list) else [raw]
    queued = 0
    dropped = 0

    for alert_raw in alerts:
        try:
            normalized = normalize_wazuh_alert(alert_raw)
            ALERT_QUEUE.put_nowait(normalized)
            queued += 1
        except asyncio.QueueFull:
            dropped += 1
            log.warning("Queue full — dropping alert")
        except Exception as e:
            log.error(f"Normalization error: {e}", exc_info=True)
            dropped += 1

    return JSONResponse({"queued": queued, "dropped": dropped, "queue_size": ALERT_QUEUE.qsize()})


@app.post("/webhook/generic")
async def generic_webhook(request: Request):
    """
    Accepts normalized alert JSON directly (for non-Wazuh sources: Elastic, Splunk, etc.)
    Required fields: rule_desc, severity (1-15), agent_id
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    alert_row = {
        "id":             str(uuid.uuid4()),
        "tenant_id":      data.get("tenant_id", TENANT_ID),
        "wazuh_alert_id": data.get("alert_id") or str(uuid.uuid4()),
        "agent_id":       data.get("agent_id", "unknown"),
        "rule_id":        data.get("rule_id"),
        "rule_desc":      data.get("rule_desc", "Generic alert"),
        "severity":       max(1, min(15, int(data.get("severity", 5)))),
        "occurred_at":    data.get("occurred_at", datetime.now(timezone.utc).isoformat()),
        "status":         "open",
        "source_platform": data.get("source_platform", "generic"),
        "event_type":     data.get("event_type", "generic_alert"),
        "threat_intel":   data.get("threat_intel"),
        "raw_event":      data,
    }

    try:
        ALERT_QUEUE.put_nowait(alert_row)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="Ingest queue full")

    return JSONResponse({"status": "queued", "alert_id": alert_row["id"]})


@app.get("/stats")
async def ingest_stats():
    """Live ingest stats from Supabase."""
    res = supabase.from_("alerts").select(
        "status, severity, source_platform, triage_verdict"
    ).eq("tenant_id", TENANT_ID).execute()
    rows = res.data or []
    return {
        "total":        len(rows),
        "open":         sum(1 for r in rows if r["status"] == "open"),
        "queue_size":   ALERT_QUEUE.qsize(),
        "by_platform":  {p: sum(1 for r in rows if r.get("source_platform") == p)
                         for p in set(r.get("source_platform","?") for r in rows)},
        "by_verdict":   {v: sum(1 for r in rows if r.get("triage_verdict") == v)
                         for v in set(r.get("triage_verdict") or "untriaged" for r in rows)},
    }


# ── Entry ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("webhook_server:app", host="0.0.0.0", port=8001, reload=False, workers=1)
