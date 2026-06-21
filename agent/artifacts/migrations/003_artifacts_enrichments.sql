-- Migration: Artifacts + Enrichments tables
-- Part of: vakros-soc/agent/artifacts/
-- Run once in Supabase SQL editor

-- ---------------------------------------------------------------
-- Artifacts table (atomic IOC objects)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.artifacts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dedup_key       TEXT UNIQUE NOT NULL,           -- sha256(tenant:type:value)
    type            TEXT NOT NULL,                  -- ip | domain | url | file_hash | hostname | username | email | process | cve
    value           TEXT NOT NULL,
    alert_id        UUID REFERENCES public.alerts(id) ON DELETE SET NULL,
    tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
    case_id         UUID REFERENCES public.correlated_cases(id) ON DELETE SET NULL,
    tags            TEXT[] DEFAULT '{}',
    is_internal     BOOLEAN DEFAULT FALSE,
    tlp             TEXT DEFAULT 'amber',
    first_seen_in_alert TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.artifacts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "tenant_read_artifacts" ON public.artifacts
    FOR SELECT USING (
        tenant_id = auth.uid()
        OR auth.jwt() ->> 'role' IN ('soc_analyst', 'soc_manager', 'admin')
    );

CREATE POLICY "service_insert_artifacts" ON public.artifacts
    FOR INSERT WITH CHECK (true);

-- ---------------------------------------------------------------
-- Enrichments table (structured results attached to any object)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.enrichments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source          TEXT NOT NULL,      -- virustotal | abuseipdb | ai_analysis | asset_lookup | geo_ip | manual
    target_type     TEXT NOT NULL,      -- artifact | alert | case
    target_id       UUID NOT NULL,
    tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
    summary         TEXT,
    data            JSONB DEFAULT '{}',
    score           INT,                -- 0-100 maliciousness
    is_malicious    BOOLEAN,
    tags            TEXT[] DEFAULT '{}',
    provider        TEXT,
    link            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.enrichments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "tenant_read_enrichments" ON public.enrichments
    FOR SELECT USING (
        tenant_id = auth.uid()
        OR auth.jwt() ->> 'role' IN ('soc_analyst', 'soc_manager', 'admin')
    );

CREATE POLICY "service_insert_enrichments" ON public.enrichments
    FOR INSERT WITH CHECK (true);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_artifacts_tenant  ON public.artifacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type    ON public.artifacts(type, value);
CREATE INDEX IF NOT EXISTS idx_artifacts_alert   ON public.artifacts(alert_id);
CREATE INDEX IF NOT EXISTS idx_enrich_target     ON public.enrichments(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_enrich_tenant     ON public.enrichments(tenant_id);
