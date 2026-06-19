-- Vakros Supabase Setup
-- Run this once in your Supabase SQL editor before ingesting documents

-- 1. Enable pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Documents table (stores chunks + embeddings)
CREATE TABLE IF NOT EXISTS documents (
    id          TEXT PRIMARY KEY,
    collection  TEXT NOT NULL,
    source      TEXT,
    chunk_index INTEGER,
    content     TEXT,
    embedding   vector(1536),   -- matches text-embedding-3-small / voyage-3 dimensions
    metadata    JSONB DEFAULT '{}'
);

-- 3. Vector similarity index (cosine distance)
CREATE INDEX IF NOT EXISTS documents_embedding_idx
    ON documents USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- 4. Collection index for fast filtering
CREATE INDEX IF NOT EXISTS documents_collection_idx
    ON documents (collection);

-- 5. Similarity search function (called by the agent retriever)
CREATE OR REPLACE FUNCTION match_documents(
    query_embedding vector(1536),
    match_collection TEXT,
    match_count INT DEFAULT 5,
    match_threshold FLOAT DEFAULT 0.7
)
RETURNS TABLE (
    id TEXT,
    content TEXT,
    source TEXT,
    metadata JSONB,
    similarity FLOAT
)
LANGUAGE SQL STABLE AS $$
    SELECT
        id,
        content,
        source,
        metadata,
        1 - (embedding <=> query_embedding) AS similarity
    FROM documents
    WHERE collection = match_collection
      AND 1 - (embedding <=> query_embedding) > match_threshold
    ORDER BY similarity DESC
    LIMIT match_count;
$$;

-- 6. Incidents table (for escalations)
CREATE TABLE IF NOT EXISTS incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    summary         TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    status          TEXT NOT NULL DEFAULT 'PENDING_ANALYST_REVIEW',
    reason          TEXT,
    raw_agent_output JSONB,
    assigned_to     TEXT,
    resolved_at     TIMESTAMPTZ
);

-- 7. Query log (optional — for observability)
CREATE TABLE IF NOT EXISTS query_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    query       TEXT,
    collection  TEXT,
    severity    TEXT,
    escalated   BOOLEAN,
    latency_ms  INTEGER
);
