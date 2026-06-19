"""
Vakros Temporal Knowledge Graph
Inspired by: https://github.com/patchy631/ai-engineering-hub/tree/main/graphiti-mcp
             https://github.com/getzep/graphiti

Implements the Graphiti pattern (entity + temporal edge graph) natively on
Supabase/Postgres — no Neo4j required. The SOC agent builds a graph of
entities (hosts, IPs, users, techniques, campaigns) and relations between
them as it investigates alerts. Over time it can answer:

  "Show me every host this IP has connected to in the last 30 days"
  "What MITRE techniques has this campaign used across this tenant?"
  "Trace the lateral movement path from the initial beachhead to DC-01"

Usage:
    from memory.graph_memory import GraphMemory

    gm = GraphMemory(tenant_id="tenant-abc")

    # After an investigation, add entities + edges
    host_id = gm.add_entity("host", "WIN-CORP-01", severity="HIGH",
                             tags=["T1486", "ransomware"])
    ip_id   = gm.add_entity("ip", "185.220.101.5", tags=["c2", "tor-exit"])
    gm.add_relation(ip_id, host_id, "connected_to",
                    alert_ids=["alert-uuid"], confidence=0.95)

    # During investigation, query attack path
    path = gm.query_attack_path("host", "WIN-CORP-01", max_hops=2)
    context = gm.format_for_agent(path)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from supabase import create_client, Client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]

_sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Valid entity types
ENTITY_TYPES = {"host", "ip", "user", "technique", "campaign", "domain", "hash", "cve"}

# Valid relation types
RELATION_TYPES = {
    "lateral_moved_to",
    "connected_to",
    "exploited_by",
    "uses_technique",
    "attributed_to",
    "member_of",
    "dropped",
    "communicates_with",
    "escalated_to",
    "targeted",
}


class GraphMemory:
    """
    Temporal knowledge graph for a single tenant.

    All entity lookups and writes are scoped to tenant_id.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    # ── Entity operations ─────────────────────────────────────────────────────

    def add_entity(
        self,
        entity_type: str,
        entity_value: str,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[list[str]] = None,
        properties: Optional[dict] = None,
    ) -> Optional[str]:
        """
        Upsert an entity. Returns the entity UUID.
        If it already exists, updates last_seen + merges tags.
        """
        try:
            now = datetime.now(timezone.utc).isoformat()

            # Check if exists
            existing = (
                _sb.table("kg_entities")
                .select("id, tags")
                .eq("tenant_id", self.tenant_id)
                .eq("entity_type", entity_type)
                .eq("entity_value", entity_value)
                .limit(1)
                .execute()
            ).data

            if existing:
                row = existing[0]
                merged_tags = list(set((row.get("tags") or []) + (tags or [])))
                _sb.table("kg_entities").update({
                    "last_seen": now,
                    "tags": merged_tags,
                    **({"severity": severity} if severity else {}),
                    **({"description": description} if description else {}),
                    **({"properties": properties} if properties else {}),
                }).eq("id", row["id"]).execute()
                return row["id"]
            else:
                result = _sb.table("kg_entities").insert({
                    "tenant_id": self.tenant_id,
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "description": description,
                    "severity": severity,
                    "tags": tags or [],
                    "properties": properties or {},
                    "first_seen": now,
                    "last_seen": now,
                }).execute()
                return result.data[0]["id"] if result.data else None
        except Exception as e:
            print(f"[GraphMemory] add_entity error: {e}")
            return None

    def get_entity_id(self, entity_type: str, entity_value: str) -> Optional[str]:
        """Look up the UUID of an existing entity."""
        try:
            result = (
                _sb.table("kg_entities")
                .select("id")
                .eq("tenant_id", self.tenant_id)
                .eq("entity_type", entity_type)
                .eq("entity_value", entity_value)
                .limit(1)
                .execute()
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            print(f"[GraphMemory] get_entity_id error: {e}")
            return None

    # ── Edge operations ───────────────────────────────────────────────────────

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        alert_ids: Optional[list[str]] = None,
        confidence: float = 1.0,
        properties: Optional[dict] = None,
    ) -> Optional[str]:
        """Record a directed relation between two entities."""
        try:
            result = _sb.table("kg_edges").insert({
                "tenant_id": self.tenant_id,
                "source_id": source_id,
                "target_id": target_id,
                "relation": relation,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "alert_ids": alert_ids or [],
                "confidence": confidence,
                "properties": properties or {},
            }).execute()
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            print(f"[GraphMemory] add_relation error: {e}")
            return None

    # ── Query operations ──────────────────────────────────────────────────────

    def query_attack_path(
        self,
        entity_type: str,
        entity_value: str,
        max_hops: int = 2,
    ) -> list[dict]:
        """
        Return the attack path (edges) around an entity up to max_hops away.
        Uses the get_entity_timeline SQL function for the first entity,
        then follows edges breadth-first for additional hops.
        """
        try:
            rows = _sb.rpc("get_entity_timeline", {
                "p_entity_type": entity_type,
                "p_entity_value": entity_value,
                "p_tenant_id": self.tenant_id,
                "p_limit": 30,
            }).execute().data or []

            if max_hops <= 1 or not rows:
                return rows

            # For hop 2: collect all connected entities and get their edges
            seen_values = {entity_value}
            hop2_rows = []
            connected = set()
            for r in rows:
                if r["source_value"] != entity_value:
                    connected.add((r["source_type"], r["source_value"]))
                if r["target_value"] != entity_value:
                    connected.add((r["target_type"], r["target_value"]))

            for etype, evalue in list(connected)[:5]:  # cap at 5 neighbors
                if evalue not in seen_values:
                    seen_values.add(evalue)
                    sub = _sb.rpc("get_entity_timeline", {
                        "p_entity_type": etype,
                        "p_entity_value": evalue,
                        "p_tenant_id": self.tenant_id,
                        "p_limit": 10,
                    }).execute().data or []
                    hop2_rows.extend(sub)

            return rows + hop2_rows

        except Exception as e:
            print(f"[GraphMemory] query_attack_path error: {e}")
            return []

    def get_entity_history(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 20,
    ) -> list[dict]:
        """Return the full temporal edge history for a single entity."""
        try:
            return _sb.rpc("get_entity_timeline", {
                "p_entity_type": entity_type,
                "p_entity_value": entity_value,
                "p_tenant_id": self.tenant_id,
                "p_limit": limit,
            }).execute().data or []
        except Exception as e:
            print(f"[GraphMemory] get_entity_history error: {e}")
            return []

    def search_entities(
        self,
        entity_type: Optional[str] = None,
        tags: Optional[list[str]] = None,
        limit: int = 20,
    ) -> list[dict]:
        """Find entities by type and/or tags for this tenant."""
        try:
            q = _sb.table("kg_entities").select("*").eq("tenant_id", self.tenant_id)
            if entity_type:
                q = q.eq("entity_type", entity_type)
            if tags:
                q = q.overlaps("tags", tags)
            return q.order("last_seen", desc=True).limit(limit).execute().data or []
        except Exception as e:
            print(f"[GraphMemory] search_entities error: {e}")
            return []

    # ── Formatting ────────────────────────────────────────────────────────────

    def format_for_agent(self, edges: list[dict]) -> str:
        """
        Render graph edges as a readable attack path for agent context injection.

        Example output:
            Attack graph context (8 edges):
            [2026-06-18 03:21] 185.220.101.5 (ip) --connected_to--> WIN-CORP-01 (host)
            [2026-06-18 03:22] WIN-CORP-01 (host) --lateral_moved_to--> DC-01 (host)
            [2026-06-18 03:25] WIN-CORP-01 (host) --uses_technique--> T1486 Data Encrypted... (technique)
        """
        if not edges:
            return "No prior attack graph entries found for this entity."

        lines = [f"Attack graph context ({len(edges)} edges):"]
        seen = set()
        for e in edges:
            key = f"{e.get('source_value')}→{e.get('relation')}→{e.get('target_value')}"
            if key in seen:
                continue
            seen.add(key)
            ts = str(e.get("observed_at", ""))[:16]
            lines.append(
                f"  [{ts}] {e.get('source_value')} ({e.get('source_type')}) "
                f"--{e.get('relation')}--> "
                f"{e.get('target_value')} ({e.get('target_type')})"
            )
        return "\n".join(lines)


# ── Convenience: extract entities from agent result and build graph ───────────

def build_graph_from_verdict(
    tenant_id: str,
    alert_id: str,
    host: Optional[str],
    source_ip: Optional[str],
    mitre_techniques: list[str],
    verdict: str,
    severity: str,
    campaign: Optional[str] = None,
) -> None:
    """
    After the agent produces a verdict, automatically extract entities
    from the result and write them into the knowledge graph.

    Call this from soc_agent.py after run_agent() completes.
    """
    gm = GraphMemory(tenant_id=tenant_id)
    alert_ids = [alert_id] if alert_id else []

    host_id = None
    ip_id = None

    if host:
        host_id = gm.add_entity("host", host, severity=severity,
                                 tags=mitre_techniques)
    if source_ip:
        ip_id = gm.add_entity("ip", source_ip, tags=mitre_techniques)

    # IP → Host connection
    if host_id and ip_id:
        gm.add_relation(ip_id, host_id, "connected_to",
                        alert_ids=alert_ids, confidence=0.9)

    # Technique nodes + edges
    for tech_id in mitre_techniques:
        tech_node_id = gm.add_entity("technique", tech_id, tags=[verdict])
        if host_id and tech_node_id:
            gm.add_relation(host_id, tech_node_id, "exploited_by",
                            alert_ids=alert_ids, confidence=0.85)

    # Campaign attribution
    if campaign and ip_id:
        camp_id = gm.add_entity("campaign", campaign, severity=severity)
        if camp_id:
            gm.add_relation(ip_id, camp_id, "attributed_to",
                            alert_ids=alert_ids)
