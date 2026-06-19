-- HITL Approvals table for Supabase
-- Run via: supabase migration new hitl_approvals

CREATE TABLE IF NOT EXISTS hitl_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    action          TEXT NOT NULL,
    action_params   JSONB NOT NULL DEFAULT '{}',
    risk_level      TEXT NOT NULL CHECK (risk_level IN ('low','medium','high','critical')),
    justification   TEXT NOT NULL DEFAULT '',
    alert_id        TEXT,
    case_id         TEXT,
    requested_by    TEXT NOT NULL DEFAULT 'soc_agent',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','denied','timeout','auto_approved')),
    approved_by     TEXT,
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

-- Index for dashboard queries (pending approvals per tenant)
CREATE INDEX IF NOT EXISTS idx_hitl_approvals_tenant_status
    ON hitl_approvals (tenant_id, status, created_at DESC);

-- RLS: analysts can read their tenant's approvals; SOC manager can approve
ALTER TABLE hitl_approvals ENABLE ROW LEVEL SECURITY;

CREATE POLICY "tenant_read_hitl" ON hitl_approvals
    FOR SELECT USING (
        tenant_id = (SELECT tenant_id FROM profiles WHERE id = auth.uid())
    );

CREATE POLICY "soc_manager_update_hitl" ON hitl_approvals
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM profiles
            WHERE id = auth.uid()
            AND role IN ('soc_manager','admin')
            AND tenant_id = hitl_approvals.tenant_id
        )
    );

-- Service role can insert (from agent)
CREATE POLICY "service_insert_hitl" ON hitl_approvals
    FOR INSERT WITH CHECK (true);

COMMENT ON TABLE hitl_approvals IS
    'Human-in-the-loop approval requests for high-risk SOC actions. Surfaced at app.vakros.com/approvals.';
