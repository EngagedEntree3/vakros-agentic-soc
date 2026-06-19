"""
Vakros Alert Ingestion Layer
Redis Stream-based async alert ingestion pipeline.

Inspired by agentic-soc-platform's Module Engine pattern:
  "Alerts arrive via Redis Streams. The Module Engine reads from the stream,
   normalizes to OCSF, extracts artifacts, correlates into cases, and routes
   to the agent orchestration graph — all asynchronously, with back-pressure
   handling and consumer groups for horizontal scaling."

Architecture:
  Webhook/SIEM → Redis Stream (vakros:alerts:{tenant_id})
    └─ RedisStreamConsumer (consumer group per tenant)
         └─ [OCSF Normalizer]
              └─ [Alert Correlator]
                   └─ [Artifact Extractor]
                        └─ [Agent Orchestration Graph]
"""

from .redis_stream import RedisStreamIngestion, AlertMessage, IngestionMetrics

__all__ = ["RedisStreamIngestion", "AlertMessage", "IngestionMetrics"]
