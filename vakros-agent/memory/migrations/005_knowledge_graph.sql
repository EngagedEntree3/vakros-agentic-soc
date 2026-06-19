-- Vakros Temporal Knowledge Graph
-- Migration 005 — run in Supabase SQL editor
--
-- Implements the Graphiti pattern (from Zep AI) on Postgres/Supabase.
-- Stores entities (hosts, IPs, users, techniques, campaigns) and
-- temporal edges (how they relate, when observed, which alerts triggered it).
--
-- This lets the SOC agent answer:
--   "How did this attacker move through the network?"
--   "Have we seen this IP talking to any of our hosts before?"
--   "What MITRE techniques is this campaign using across tenants?"

-- ── Entity types ─────────────────────────────────────────────────────────────
-- host       : endpoint hostname or FQDN        e.g. "WIN-CORP-01"
-- ip         : IP address (internal or external) e.g. "185.220.101.5"
-- user       : user account                      e.g. "jsmith@company.com"
-- technique  : MITRE ATT&CK technique            e.g. "T1486 Data Encrypted for Impact"
-- campaign   : named threat campaign/actor        e.g. "LockBit 3.0"
-- domain     : network domain or FQDN            e.g. "malicious-c2.xyz"
-- hash       : file hash (MD5/SHA256)             e.g. "d41d8cd98f00b204..."
-- cve        : vulnerability                      e.g. "CVE-2024-1234"

CREATE TABLE IF NOT EXISTS kg_entities (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    description  TEXT,
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_seen    TIMESTAMPTZ DEFAULT NOW(),
    severity     TEXT,
    tags         TEXT[] DEFAULT '{}',
    properties   JSONB DEFAULT '{}',
    UNIQUE (tenant_id, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS kg_entities_tenant_type_idx
    ON kg_entities (tenant_id, entity_type);

CREATE INDEX IF NOT EXISTS kg_entities_tenant_value_idx
    ON kg_entities (tenant_id, entity_value);

CREATE INDEX IF NOT EXISTS kg_entities_tags_idx
    ON kg_entities USING GIN (tags);

-- ── Edge / relation types ─────────────────────────────────────────────────────
-- lateral_moved_to    : host → host via lateral movement
-- connected_to        : ip/domain ↔ host (network connection)
-- exploited_by        : host/cve ← technique/campaign
-- uses_technique      : campaign → technique
-- attributed_to       : ip/domain → campaign
-- member_of           : user → host (logged in / owns)
-- dropped             : host → hash (file created/executed)
-- communicates_with   : host → domain/ip (C2, exfil)
-- escalated_to        : technique → technique (priv esc chain)

CREATE TABLE IF NOT EXISTS kg_edges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    source_id       UUID NOT NULL REFERENCES kg_entities(id) ON DELETE CASCADE,
    target_id       UUID NOT NULL REFERENCES kg_entities(id) ON DELETE CASCADE,
    relation        TEXT NOT NULL,
    observed_at     TIMESTAMPTZ DEFAULT NOW(),
    alert_ids       TEXT[] DEFAULT '{}',
    confidence      FLOAT DEFAULT 1.0,
    properties      JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS kg_edges_tenant_idx
    ON kg_edges (tenant_id);

CREATE INDEX IF NOT EXISTS kg_edges_source_idx
    ON kg_edges (source_id);

CREATE INDEX IF NOT EXISTS kg_edges_target_idx
    ON kg_edges (target_id);

CREATE INDEX IF NOT EXISTS kg_edges_relation_idx
    ON kg_edges (tenant_id, relation);

-- ── Attack path query function ────────────────────────────────────────────────
-- Returns all edges (hops) connected to a given entity (1 hop out).
-- For multi-hop traversal the Python layer iterates.

CREATE OR REPLACE FUNCTION get_entity_neighbors(
    p_entity_id   UUID,
    p_tenant_id   TEXT,
    p_max_hops    INT DEFAULT 1
)
RETURNS TABLE (
    source_type   TEXT,
    source_value  TEXT,
    relation      TEXT,
    target_type   TEXT,
    target_value  TEXT,
    observed_at   TIMESTAMPTZ,
    alert_ids     TEXT[],
    confidence    FLOAT
)
LANGUAGE SQL STABLE AS $$
    SELECT
        s.entity_type  AS source_type,
        s.entity_value AS source_value,
        e.relation,
        t.entity_type  AS target_type,
        t.entity_value AS target_value,
        e.observed_at,
        e.alert_ids,
        e.confidence
    FROM kg_edges e
    JOIN kg_entities s ON s.id = e.source_id
    JOIN kg_entities t ON t.id = e.target_id
    WHERE e.tenant_id = p_tenant_id
      AND (e.source_id = p_entity_id OR e.target_id = p_entity_id)
    ORDER BY e.observed_at DESC;
$$;

-- ── Entity timeline function ──────────────────────────────────────────────────
-- Returns all edges for an entity ordered by time (full timeline).

CREATE OR REPLACE FUNCTION get_entity_timeline(
    p_entity_type  TEXT,
    p_entity_value TEXT,
    p_tenant_id    TEXT,
    p_limit        INT DEFAULT 20
)
RETURNS TABLE (
    observed_at   TIMESTAMPTZ,
    source_type   TEXT,
    source_value  TEXT,
    relation      TEXT,
    target_type   TEXT,
    target_value  TEXT,
    alert_ids     TEXT[]
)
LANGUAGE SQL STABLE AS $$
    SELECT
        e.observed_at,
        s.entity_type,
        s.entity_value,
        e.relation,
        t.entity_type,
        t.entity_value,
        e.alert_ids
    FROM kg_edges e
    JOIN kg_entities s ON s.id = e.source_id
    JOIN kg_entities t ON t.id = e.target_id
    WHERE e.tenant_id = p_tenant_id
      AND (
          (s.entity_type = p_entity_type AND s.entity_value = p_entity_value)
          OR
          (t.entity_type = p_entity_type AND t.entity_value = p_entity_value)
      )
    ORDER BY e.observed_at DESC
    LIMIT p_limit;
$$;
