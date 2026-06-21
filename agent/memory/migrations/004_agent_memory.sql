-- Vakros Agent Memory Table
-- Migration 004 — run in Supabase SQL editor

CREATE TABLE IF NOT EXISTS agent_memory (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT NOT NULL,
    entity_type  TEXT NOT NULL,   -- 'host', 'ip', 'domain', 'hash', 'user', 'alert_type'
    entity_value TEXT NOT NULL,
    summary      TEXT NOT NULL,
    severity     TEXT,            -- CRITICAL / HIGH / MEDIUM / LOW
    verdict      TEXT,            -- true_positive / false_positive / benign / needs_investigation
    alert_ids    TEXT[] DEFAULT '{}',
    tags         TEXT[] DEFAULT '{}',  -- MITRE IDs, threat actor names, attack categories
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Lookup index (most common query: tenant + entity)
CREATE INDEX IF NOT EXISTS agent_memory_tenant_entity_idx
    ON agent_memory (tenant_id, entity_type, entity_value);

-- Tag search index
CREATE INDEX IF NOT EXISTS agent_memory_tags_idx
    ON agent_memory USING GIN (tags);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_agent_memory_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_memory_updated_at_trigger ON agent_memory;
CREATE TRIGGER agent_memory_updated_at_trigger
    BEFORE UPDATE ON agent_memory
    FOR EACH ROW EXECUTE FUNCTION update_agent_memory_updated_at();

-- query_log table update: add trace_id and verdict columns if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'query_log' AND column_name = 'trace_id'
    ) THEN
        ALTER TABLE query_log
            ADD COLUMN trace_id TEXT,
            ADD COLUMN verdict   TEXT,
            ADD COLUMN confidence FLOAT,
            ADD COLUMN iterations INT,
            ADD COLUMN tools_called TEXT[];
    END IF;
END $$;
