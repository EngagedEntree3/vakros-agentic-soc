-- Migration: Correlated Cases (Alert Correlation Engine)
-- Part of: vakros-soc/agent/correlation/
-- Run once in Supabase SQL editor

-- Correlated Cases table
CREATE TABLE IF NOT EXISTS public.correlated_cases (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_uid   TEXT UNIQUE NOT NULL,
    rule_name         TEXT NOT NULL,
    tenant_id         UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
    title             TEXT NOT NULL,
    severity          INT DEFAULT 0,
    alert_count       INT DEFAULT 0,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status            TEXT NOT NULL DEFAULT 'open',  -- open / in_progress / closed / false_positive
    tags              TEXT[] DEFAULT '{}',
    enrichments       JSONB DEFAULT '[]',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS
ALTER TABLE public.correlated_cases ENABLE ROW LEVEL SECURITY;

CREATE POLICY "tenant_read_cases" ON public.correlated_cases
    FOR SELECT USING (
        tenant_id = auth.uid()
        OR auth.jwt() ->> 'role' IN ('soc_analyst', 'soc_manager', 'admin')
    );

CREATE POLICY "service_insert_cases" ON public.correlated_cases
    FOR INSERT WITH CHECK (true);

CREATE POLICY "soc_update_cases" ON public.correlated_cases
    FOR UPDATE USING (
        auth.jwt() ->> 'role' IN ('soc_analyst', 'soc_manager', 'admin')
    );

-- Add correlation columns to alerts (idempotent)
ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS correlation_uid        TEXT,
    ADD COLUMN IF NOT EXISTS correlated_case_id     UUID REFERENCES public.correlated_cases(id);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_uid ON public.alerts(correlation_uid);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_created  ON public.alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_tenant_status    ON public.correlated_cases(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_cases_uid              ON public.correlated_cases(correlation_uid);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_cases_updated_at ON public.correlated_cases;
CREATE TRIGGER trg_cases_updated_at
    BEFORE UPDATE ON public.correlated_cases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
