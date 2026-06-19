"""
Redis Stream Alert Ingestion Pipeline
Async consumer for the Vakros Agentic SOC event bus.

Inspired by agentic-soc-platform Module Engine:
  "Redis Streams provide a durable, ordered, replayable event log.
   Consumer groups allow horizontal scaling across multiple worker instances.
   XACK ensures at-least-once delivery with manual acknowledgement."

Stream naming convention:
  vakros:alerts:{tenant_id}          — per-tenant alert stream
  vakros:alerts:global               — cross-tenant admin stream (Vakros ops only)

Consumer group naming:
  vakros-soc-engine:{tenant_id}      — one group per tenant pipeline

Usage:
    ingestion = RedisStreamIngestion(redis_url="redis://localhost:6379")
    await ingestion.start_consuming(tenant_id="abc123")

    # Or push directly (for testing/webhook use):
    await ingestion.push_alert(alert_dict, tenant_id="abc123")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

# Stream / consumer group configuration
STREAM_PREFIX      = "vakros:alerts"
CONSUMER_GROUP     = "vakros-soc-engine"
CONSUMER_NAME      = f"worker-{uuid4().hex[:8]}"
BLOCK_MS           = 5_000      # block for 5s on XREAD if no messages
MAX_MESSAGES       = 10         # process up to 10 messages per read
BACKOFF_MAX_S      = 30         # max backoff on connection error
ACK_RETRY_LIMIT    = 3          # retry limit before dead-lettering


@dataclass
class AlertMessage:
    """A single alert message read from the Redis stream."""
    stream_id: str           # Redis message ID (e.g. "1718000000000-0")
    tenant_id: str
    alert_raw: dict          # raw alert payload from SIEM/webhook
    source: str = "unknown"  # wazuh | elastic | splunk | webhook | manual
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0
    error: str | None = None

    @classmethod
    def from_redis_entry(cls, stream_id: str, fields: dict, tenant_id: str) -> "AlertMessage":
        """Parse a Redis stream entry into an AlertMessage."""
        payload_raw = fields.get(b"payload", fields.get("payload", b"{}"))
        if isinstance(payload_raw, bytes):
            payload_raw = payload_raw.decode()
        try:
            payload = json.loads(payload_raw)
        except json.JSONDecodeError:
            payload = {"raw": payload_raw}

        source_raw = fields.get(b"source", fields.get("source", b"unknown"))
        source = source_raw.decode() if isinstance(source_raw, bytes) else str(source_raw)

        return cls(
            stream_id=stream_id,
            tenant_id=tenant_id,
            alert_raw=payload,
            source=source,
        )


@dataclass
class IngestionMetrics:
    """Rolling metrics for the ingestion pipeline."""
    messages_received: int = 0
    messages_processed: int = 0
    messages_failed: int = 0
    messages_dead_lettered: int = 0
    last_message_at: datetime | None = None
    pipeline_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def throughput_per_min(self) -> float:
        elapsed_s = (datetime.now(timezone.utc) - self.pipeline_start).total_seconds()
        return (self.messages_processed / elapsed_s * 60) if elapsed_s > 0 else 0.0

    def error_rate(self) -> float:
        total = self.messages_received or 1
        return self.messages_failed / total


class RedisStreamIngestion:
    """
    Redis Stream-based alert ingestion pipeline for the Vakros Agentic SOC.

    Responsibilities:
    1. Consume alerts from per-tenant Redis streams
    2. Normalize via OCSF normalizer
    3. Correlate via AlertCorrelator
    4. Extract artifacts via ArtifactExtractor
    5. Route to AgentGraph for triage

    Design:
    - Uses Redis consumer groups for horizontal scaling
    - Per-tenant streams for data isolation
    - XACK-based at-least-once delivery
    - Dead-letter queue for unprocessable messages
    - Metrics export for n8n monitoring hook
    """

    def __init__(
        self,
        redis_url: str | None = None,
        supabase_client: Any = None,
        anthropic_api_key: str | None = None,
        max_concurrent_alerts: int = 5,
    ):
        self._redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self._sb = supabase_client
        self._anthropic_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self._max_concurrent = max_concurrent_alerts
        self._metrics: dict[str, IngestionMetrics] = {}
        self._running: dict[str, bool] = {}
        self._redis: Any = None   # redis.asyncio client, set at start

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def push_alert(
        self,
        alert: dict,
        tenant_id: str,
        source: str = "webhook",
    ) -> str:
        """
        Push a single alert onto the tenant's Redis stream.
        Returns the Redis stream message ID.

        Used by:
        - Webhook server (wazuh_integration/webhook_server.py)
        - n8n SIEM adapter workflow
        - Manual alert injection for testing
        """
        r = await self._get_redis()
        stream_key = f"{STREAM_PREFIX}:{tenant_id}"
        payload = {
            "payload": json.dumps(alert, default=str),
            "source": source,
            "tenant_id": tenant_id,
            "pushed_at": datetime.now(timezone.utc).isoformat(),
        }
        msg_id = await r.xadd(stream_key, payload)
        logger.debug("Pushed alert to stream %s: id=%s", stream_key, msg_id)
        return msg_id if isinstance(msg_id, str) else msg_id.decode()

    async def start_consuming(
        self,
        tenant_id: str,
        block_ms: int = BLOCK_MS,
    ) -> None:
        """
        Start the consumer loop for a single tenant.
        Creates consumer group if it doesn't exist.
        Runs indefinitely until stop_consuming() is called.
        """
        stream_key = f"{STREAM_PREFIX}:{tenant_id}"
        group_name = f"{CONSUMER_GROUP}:{tenant_id}"

        r = await self._get_redis()
        await self._ensure_group(r, stream_key, group_name)

        self._running[tenant_id] = True
        self._metrics[tenant_id] = IngestionMetrics()
        backoff = 1

        logger.info(
            "Starting Redis stream consumer: stream=%s group=%s consumer=%s",
            stream_key, group_name, CONSUMER_NAME
        )

        while self._running.get(tenant_id, False):
            try:
                messages = await r.xreadgroup(
                    groupname=group_name,
                    consumername=CONSUMER_NAME,
                    streams={stream_key: ">"},
                    count=MAX_MESSAGES,
                    block=block_ms,
                )

                if not messages:
                    # Also process pending (unacked) messages from previous runs
                    await self._process_pending(r, stream_key, group_name, tenant_id)
                    continue

                backoff = 1  # reset backoff on successful read
                alert_msgs = []
                for _, entries in messages:
                    for stream_id, fields in entries:
                        sid = stream_id.decode() if isinstance(stream_id, bytes) else stream_id
                        msg = AlertMessage.from_redis_entry(sid, fields, tenant_id)
                        alert_msgs.append(msg)
                        self._metrics[tenant_id].messages_received += 1

                # Process alerts concurrently (bounded by semaphore)
                sem = asyncio.Semaphore(self._max_concurrent)
                tasks = [
                    self._process_with_semaphore(sem, msg, r, group_name, stream_key)
                    for msg in alert_msgs
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

            except Exception as exc:
                if "redis" in str(type(exc).__module__).lower():
                    logger.error("Redis connection error: %s — backing off %ds", exc, backoff)
                    await asyncio.sleep(min(backoff, BACKOFF_MAX_S))
                    backoff = min(backoff * 2, BACKOFF_MAX_S)
                    self._redis = None  # force reconnect
                else:
                    logger.error("Consumer loop error: %s", exc, exc_info=True)
                    await asyncio.sleep(1)

    async def stop_consuming(self, tenant_id: str) -> None:
        """Gracefully stop the consumer for a tenant."""
        self._running[tenant_id] = False
        logger.info("Stopping consumer for tenant %s", tenant_id)

    async def start_consuming_all_tenants(self) -> None:
        """
        Start consumers for ALL active tenants from Supabase.
        Designed for the main worker entry point.
        """
        if not self._sb:
            raise RuntimeError("Supabase client required for multi-tenant consumption")

        res = self._sb.table("tenants").select("id").eq("status", "active").execute()
        tenant_ids = [row["id"] for row in (res.data or [])]
        logger.info("Starting consumers for %d active tenants", len(tenant_ids))

        tasks = [self.start_consuming(tid) for tid in tenant_ids]
        await asyncio.gather(*tasks, return_exceptions=True)

    def get_metrics(self, tenant_id: str) -> dict:
        """Return current ingestion metrics for a tenant."""
        m = self._metrics.get(tenant_id)
        if not m:
            return {}
        return {
            "tenant_id": tenant_id,
            "messages_received": m.messages_received,
            "messages_processed": m.messages_processed,
            "messages_failed": m.messages_failed,
            "messages_dead_lettered": m.messages_dead_lettered,
            "throughput_per_min": round(m.throughput_per_min(), 2),
            "error_rate": round(m.error_rate(), 4),
            "last_message_at": m.last_message_at.isoformat() if m.last_message_at else None,
            "running": self._running.get(tenant_id, False),
        }

    # ------------------------------------------------------------------
    # Processing pipeline
    # ------------------------------------------------------------------

    async def _process_with_semaphore(
        self,
        sem: asyncio.Semaphore,
        msg: AlertMessage,
        redis_client: Any,
        group_name: str,
        stream_key: str,
    ) -> None:
        async with sem:
            await self._process_message(msg, redis_client, group_name, stream_key)

    async def _process_message(
        self,
        msg: AlertMessage,
        redis_client: Any,
        group_name: str,
        stream_key: str,
    ) -> None:
        """
        Full pipeline for a single alert message:
        Normalize → Correlate → Extract → Orchestrate → ACK
        """
        m = self._metrics[msg.tenant_id]
        try:
            # 1. OCSF Normalization
            from ..normalization import OCSFNormalizer
            normalizer = OCSFNormalizer()
            alert_ocsf = normalizer.normalize(msg.alert_raw)
            alert_ocsf_dict = alert_ocsf.to_dict()

            # 2. Correlation (find or create a case)
            correlation_uid = ""
            case_id = ""
            try:
                from ..correlation import AlertCorrelator
                correlator = AlertCorrelator(supabase_client=self._sb)
                cases = correlator.correlate(
                    [alert_ocsf_dict],
                    tenant_id=msg.tenant_id,
                )
                if cases:
                    correlation_uid = cases[0].uid
                    case_id = cases[0].uid
            except Exception as exc:
                logger.warning("Correlation failed (non-fatal): %s", exc)

            # 3. Artifact Extraction
            artifacts = []
            enrichments = []
            try:
                from ..artifacts import ArtifactExtractor
                extractor = ArtifactExtractor()
                artifact_objs = extractor.extract(alert_ocsf_dict, msg.tenant_id)
                artifacts = [a.to_dict() for a in artifact_objs]
            except Exception as exc:
                logger.warning("Artifact extraction failed (non-fatal): %s", exc)

            # 4. Agent Orchestration Graph
            from ..orchestration import AgentGraph, GraphConfig
            config = GraphConfig(
                anthropic_api_key=self._anthropic_key,
                supabase_client=self._sb,
            )
            graph = AgentGraph(config)
            final_state = await graph.run(
                alert_ocsf=alert_ocsf_dict,
                tenant_id=msg.tenant_id,
                correlation_uid=correlation_uid,
                enrichments=enrichments,
                artifacts=artifacts,
                case_id=case_id,
            )

            logger.info(
                "Alert processed: tenant=%s stream_id=%s verdict=%s risk=%d nodes=%d",
                msg.tenant_id, msg.stream_id, final_state.final_verdict,
                final_state.risk_score, len(final_state.node_history)
            )

            # 5. ACK the message
            await redis_client.xack(stream_key, group_name, msg.stream_id)
            m.messages_processed += 1
            m.last_message_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error(
                "Failed to process alert: tenant=%s stream_id=%s error=%s",
                msg.tenant_id, msg.stream_id, exc, exc_info=True
            )
            m.messages_failed += 1
            msg.retry_count += 1
            msg.error = str(exc)

            if msg.retry_count >= ACK_RETRY_LIMIT:
                await self._dead_letter(msg, redis_client)
                await redis_client.xack(stream_key, group_name, msg.stream_id)
                m.messages_dead_lettered += 1
            # If retry_count < limit: leave in PEL (pending list) for reprocessing

    async def _process_pending(
        self,
        redis_client: Any,
        stream_key: str,
        group_name: str,
        tenant_id: str,
    ) -> None:
        """
        Process pending (unacknowledged) messages from previous consumer runs.
        Called when XREADGROUP returns no new messages.
        """
        try:
            pending = await redis_client.xpending_range(
                stream_key,
                group_name,
                min="-",
                max="+",
                count=MAX_MESSAGES,
            )
            if not pending:
                return
            logger.info("Processing %d pending messages for tenant %s", len(pending), tenant_id)
            for item in pending:
                msg_id = item["message_id"].decode() if isinstance(item["message_id"], bytes) else item["message_id"]
                # Claim and re-process
                claimed = await redis_client.xclaim(
                    stream_key, group_name, CONSUMER_NAME, 0, [msg_id]
                )
                for cid, fields in claimed:
                    cid_str = cid.decode() if isinstance(cid, bytes) else cid
                    msg = AlertMessage.from_redis_entry(cid_str, fields, tenant_id)
                    await self._process_message(msg, redis_client, group_name, stream_key)
        except Exception as exc:
            logger.warning("Failed to process pending messages: %s", exc)

    async def _dead_letter(self, msg: AlertMessage, redis_client: Any) -> None:
        """Move unprocessable message to the dead-letter stream."""
        try:
            dl_stream = f"vakros:dead-letter:{msg.tenant_id}"
            await redis_client.xadd(dl_stream, {
                "original_stream_id": msg.stream_id,
                "tenant_id": msg.tenant_id,
                "payload": json.dumps(msg.alert_raw, default=str),
                "error": msg.error or "unknown",
                "retry_count": str(msg.retry_count),
                "dead_lettered_at": datetime.now(timezone.utc).isoformat(),
            })
            logger.warning(
                "Alert dead-lettered: tenant=%s stream_id=%s error=%s",
                msg.tenant_id, msg.stream_id, msg.error
            )
        except Exception as exc:
            logger.error("Failed to dead-letter message: %s", exc)

    # ------------------------------------------------------------------
    # Redis connection management
    # ------------------------------------------------------------------

    async def _get_redis(self) -> Any:
        """Lazy connection to Redis with reconnection logic."""
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                self._redis = await aioredis.from_url(
                    self._redis_url,
                    decode_responses=False,
                    socket_timeout=5,
                    socket_connect_timeout=5,
                    retry_on_timeout=True,
                )
                await self._redis.ping()
                logger.info("Connected to Redis: %s", self._redis_url)
            except ImportError:
                raise RuntimeError(
                    "redis[asyncio] not installed. Run: pip install redis[asyncio]"
                )
        return self._redis

    async def _ensure_group(
        self,
        redis_client: Any,
        stream_key: str,
        group_name: str,
    ) -> None:
        """Create consumer group if it doesn't already exist."""
        try:
            # Create group starting from the beginning ($=latest, 0=beginning)
            await redis_client.xgroup_create(
                stream_key, group_name, id="$", mkstream=True
            )
            logger.info("Created consumer group: %s on %s", group_name, stream_key)
        except Exception as exc:
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group already exists: %s", group_name)
            else:
                raise


# ─────────────────────────────────────────────────────────────────────────────
# Webhook bridge — converts webhook payload directly to stream
# ─────────────────────────────────────────────────────────────────────────────

async def webhook_to_stream(
    alert: dict,
    tenant_id: str,
    source: str = "webhook",
    redis_url: str | None = None,
) -> str:
    """
    Convenience function for webhook_server.py:
    Push a raw webhook alert payload onto the tenant's Redis stream.

    Returns the Redis stream message ID.
    """
    ingestion = RedisStreamIngestion(redis_url=redis_url)
    return await ingestion.push_alert(alert, tenant_id=tenant_id, source=source)
