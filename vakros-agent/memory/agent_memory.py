"""
Vakros Agent Memory
Inspired by: https://github.com/patchy631/ai-engineering-hub/tree/main/database-memory-agent

Gives the SOC agent persistent, tenant-scoped memory so it can recall:
  - Prior alerts on the same host
  - Previously seen IOCs (IPs, hashes, domains)
  - Recurring attack patterns per tenant
  - Last investigation summaries for related entities

Storage: Supabase `agent_memory` table (created via migration below).
Lookup: Fuzzy + exact match on entity (host/IP/domain/hash) + tenant.

SQL migration (run once):
    CREATE TABLE IF NOT EXISTS agent_memory (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id   TEXT NOT NULL,
        entity_type TEXT NOT NULL,  -- 'host', 'ip', 'domain', 'hash', 'user'
        entity_value TEXT NOT NULL,
        summary     TEXT NOT NULL,
        severity    TEXT,
        verdict     TEXT,
        alert_ids   TEXT[] DEFAULT '{}',
        tags        TEXT[] DEFAULT '{}',
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        updated_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS agent_memory_tenant_entity
        ON agent_memory (tenant_id, entity_type, entity_value);
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from supabase import create_client, Client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]

_sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

TABLE = "agent_memory"


class AgentMemory:
    """
    Per-tenant agent memory store.

    Usage:
        mem = AgentMemory(tenant_id="tenant-abc")

        # Recall prior investigations for a host
        context = mem.recall(entity_type="host", entity_value="WIN-CORP-01")

        # Store after completing an investigation
        mem.store(
            entity_type="host",
            entity_value="WIN-CORP-01",
            summary="Ransomware precursor activity — file encryption IOCs confirmed.",
            severity="CRITICAL",
            verdict="true_positive",
            alert_ids=["alert-uuid-123"],
            tags=["ransomware", "T1486"],
        )
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def recall(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 5,
    ) -> list[dict]:
        """
        Retrieve prior investigation summaries for an entity.
        Returns most recent entries first.
        """
        try:
            result = (
                _sb.table(TABLE)
                .select("*")
                .eq("tenant_id", self.tenant_id)
                .eq("entity_type", entity_type)
                .eq("entity_value", entity_value)
                .order("updated_at", desc=True)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as e:
            print(f"[Memory] recall error: {e}")
            return []

    def recall_tags(self, tags: list[str], limit: int = 10) -> list[dict]:
        """Recall all memory entries for this tenant that match any of the given tags."""
        try:
            result = (
                _sb.table(TABLE)
                .select("*")
                .eq("tenant_id", self.tenant_id)
                .overlaps("tags", tags)
                .order("updated_at", desc=True)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as e:
            print(f"[Memory] recall_tags error: {e}")
            return []

    def store(
        self,
        entity_type: str,
        entity_value: str,
        summary: str,
        severity: Optional[str] = None,
        verdict: Optional[str] = None,
        alert_ids: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> bool:
        """
        Upsert an investigation summary for an entity.
        If a memory entry already exists for this tenant+entity, merges alert_ids and tags.
        """
        try:
            # Check for existing entry
            existing = (
                _sb.table(TABLE)
                .select("id, alert_ids, tags")
                .eq("tenant_id", self.tenant_id)
                .eq("entity_type", entity_type)
                .eq("entity_value", entity_value)
                .limit(1)
                .execute()
            ).data

            now = datetime.now(timezone.utc).isoformat()

            if existing:
                row = existing[0]
                merged_alerts = list(set((row.get("alert_ids") or []) + (alert_ids or [])))
                merged_tags = list(set((row.get("tags") or []) + (tags or [])))
                _sb.table(TABLE).update({
                    "summary": summary,
                    "severity": severity,
                    "verdict": verdict,
                    "alert_ids": merged_alerts,
                    "tags": merged_tags,
                    "updated_at": now,
                }).eq("id", row["id"]).execute()
            else:
                _sb.table(TABLE).insert({
                    "tenant_id": self.tenant_id,
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "summary": summary,
                    "severity": severity,
                    "verdict": verdict,
                    "alert_ids": alert_ids or [],
                    "tags": tags or [],
                    "updated_at": now,
                }).execute()

            return True
        except Exception as e:
            print(f"[Memory] store error: {e}")
            return False

    def format_for_agent(self, memories: list[dict]) -> str:
        """Format memory entries as context string for the agent system prompt."""
        if not memories:
            return "No prior investigations found for this entity."
        lines = ["Prior investigation context:"]
        for m in memories:
            lines.append(
                f"- [{m.get('updated_at', '')[:10]}] "
                f"{m.get('verdict', 'unknown')} | {m.get('severity', '?')} | "
                f"{m.get('summary', '')[:200]}"
            )
        return "\n".join(lines)


# ── Convenience functions ─────────────────────────────────────────────────────

def recall_context(
    tenant_id: str,
    entity_type: str,
    entity_value: str,
    limit: int = 3,
) -> str:
    """
    Quick recall — returns formatted string ready to inject into agent context.

    Example:
        ctx = recall_context("tenant-abc", "host", "WIN-CORP-01")
        # → "Prior investigation context:\n- [2026-06-15] true_positive | CRITICAL | ..."
    """
    mem = AgentMemory(tenant_id=tenant_id)
    memories = mem.recall(entity_type=entity_type, entity_value=entity_value, limit=limit)
    return mem.format_for_agent(memories)


def store_investigation(
    tenant_id: str,
    entity_type: str,
    entity_value: str,
    summary: str,
    severity: Optional[str] = None,
    verdict: Optional[str] = None,
    alert_ids: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
) -> bool:
    """Quick store — convenience wrapper around AgentMemory.store()."""
    mem = AgentMemory(tenant_id=tenant_id)
    return mem.store(
        entity_type=entity_type,
        entity_value=entity_value,
        summary=summary,
        severity=severity,
        verdict=verdict,
        alert_ids=alert_ids,
        tags=tags,
    )
