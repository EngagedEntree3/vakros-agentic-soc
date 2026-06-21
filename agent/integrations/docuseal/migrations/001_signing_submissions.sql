-- =============================================================================
-- Migration: 001_signing_submissions.sql
-- Vakros DocuSeal e-Signature Integration
-- =============================================================================
-- Creates the signing_submissions table for tracking all DocuSeal submissions.
-- Every row is tenant-isolated via RLS (Row Level Security).
--
-- Run in: Supabase SQL Editor → etmshueaqaqxpyzuvkqi (vakros-portal)
-- =============================================================================

-- ── 1. signing_submissions ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.signing_submissions (
  -- Vakros primary key
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Tenant isolation (required — RLS enforces this)
  tenant_id         UUID        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,

  -- DocuSeal references
  docuseal_id       INTEGER     NOT NULL UNIQUE,   -- DocuSeal submission.id
  template_id       INTEGER     NOT NULL,           -- DocuSeal template.id
  embed_slug        TEXT        NOT NULL,           -- DocuSeal submitter slug (used for embed URL)
  embed_src         TEXT        NOT NULL,           -- Full embed URL: https://signing.vakros.com/s/{slug}

  -- Signer info
  signer_email      TEXT        NOT NULL,
  signer_name       TEXT,
  signer_role       TEXT        NOT NULL DEFAULT 'Signer',

  -- Status lifecycle: pending → started → viewed → completed | declined
  status            TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'started', 'viewed', 'completed', 'declined')),

  -- Timestamps
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at        TIMESTAMPTZ,
  viewed_at         TIMESTAMPTZ,
  completed_at      TIMESTAMPTZ,
  declined_at       TIMESTAMPTZ,

  -- Flexible metadata (template-specific fields, deal IDs, etc.)
  metadata          JSONB       NOT NULL DEFAULT '{}'::jsonb,

  -- Audit
  created_by        UUID        REFERENCES auth.users(id),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── 2. Indexes ────────────────────────────────────────────────────────────────

-- Fast lookup by DocuSeal ID (used in webhook handler)
CREATE INDEX IF NOT EXISTS idx_signing_submissions_docuseal_id
  ON public.signing_submissions (docuseal_id);

-- Fast lookup by tenant (used in dashboard listing)
CREATE INDEX IF NOT EXISTS idx_signing_submissions_tenant_id
  ON public.signing_submissions (tenant_id);

-- Fast lookup by signer email (used for "find my documents")
CREATE INDEX IF NOT EXISTS idx_signing_submissions_signer_email
  ON public.signing_submissions (signer_email);

-- Fast status filter
CREATE INDEX IF NOT EXISTS idx_signing_submissions_status
  ON public.signing_submissions (tenant_id, status);

-- ── 3. updated_at trigger ─────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS signing_submissions_updated_at ON public.signing_submissions;
CREATE TRIGGER signing_submissions_updated_at
  BEFORE UPDATE ON public.signing_submissions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ── 4. Row Level Security ─────────────────────────────────────────────────────

ALTER TABLE public.signing_submissions ENABLE ROW LEVEL SECURITY;

-- Tenants can only see their own submissions
CREATE POLICY signing_tenant_select ON public.signing_submissions
  FOR SELECT
  USING (tenant_id = (current_setting('app.tenant_id', true))::uuid);

-- Tenants can only insert for themselves
CREATE POLICY signing_tenant_insert ON public.signing_submissions
  FOR INSERT
  WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

-- Tenants can only update their own rows (status, timestamps)
CREATE POLICY signing_tenant_update ON public.signing_submissions
  FOR UPDATE
  USING (tenant_id = (current_setting('app.tenant_id', true))::uuid);

-- Service role bypass (used by Vakros backend + n8n Supabase node)
CREATE POLICY signing_service_role_all ON public.signing_submissions
  FOR ALL
  USING (auth.role() = 'service_role');

-- ── 5. Supabase Realtime (optional — enables live status updates in frontend) ──

ALTER PUBLICATION supabase_realtime ADD TABLE public.signing_submissions;

-- ── 6. signing_templates cache (optional — reduces DocuSeal API calls) ─────────

CREATE TABLE IF NOT EXISTS public.signing_templates (
  id              SERIAL      PRIMARY KEY,
  docuseal_id     INTEGER     NOT NULL UNIQUE,
  name            TEXT        NOT NULL,
  description     TEXT,
  fields          JSONB       NOT NULL DEFAULT '[]'::jsonb,
  is_active       BOOLEAN     NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.signing_templates ENABLE ROW LEVEL SECURITY;

-- All authenticated users can read templates (they're not tenant-specific)
CREATE POLICY signing_templates_read ON public.signing_templates
  FOR SELECT
  USING (auth.role() IN ('authenticated', 'service_role'));

-- Only service role can insert/update (synced from DocuSeal)
CREATE POLICY signing_templates_write ON public.signing_templates
  FOR ALL
  USING (auth.role() = 'service_role');

-- ── 7. Helpful view for dashboard ─────────────────────────────────────────────

CREATE OR REPLACE VIEW public.v_signing_submissions_summary AS
SELECT
  s.id,
  s.tenant_id,
  s.docuseal_id,
  t.name           AS template_name,
  s.signer_email,
  s.signer_name,
  s.status,
  s.created_at,
  s.completed_at,
  s.declined_at,
  CASE
    WHEN s.status = 'completed' THEN '✅ Signed'
    WHEN s.status = 'declined'  THEN '❌ Declined'
    WHEN s.status = 'viewed'    THEN '👁 Viewed'
    WHEN s.status = 'started'   THEN '✍ In Progress'
    ELSE '⏳ Pending'
  END              AS status_label,
  EXTRACT(EPOCH FROM (s.completed_at - s.created_at)) / 3600
                   AS hours_to_complete
FROM public.signing_submissions s
LEFT JOIN public.signing_templates t ON t.docuseal_id = s.template_id;

-- Grant read access to authenticated users (RLS on base table still applies)
GRANT SELECT ON public.v_signing_submissions_summary TO authenticated;

-- ── Done ──────────────────────────────────────────────────────────────────────
-- Run migration 002 next if you need document audit trail per-field.
