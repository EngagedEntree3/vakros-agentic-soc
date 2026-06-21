# Rollback Runbook — Vakros Agentic SOC Agent Engine
**gstack v1 | Owned by: Release Manager Agent**  
**Last reviewed:** 2026-06-17

## Prerequisites
- GitHub repo access: `EngagedEntree3/vakros-agentic-soc`
- Supabase project admin access
- n8n admin access

## Rollback Triggers (when to activate)

Activate this runbook if ANY of the following occur after a production deployment:

| Trigger | Severity | SLA |
|---|---|---|
| Prompt regression detection rate drops below 95% | P1 | Immediate |
| HITL gate bypassed — agent acted autonomously on blocked action | P0 | Immediate |
| Cross-tenant data leakage detected | P0 | Immediate |
| SOC1 false negative rate > 1% (real threat classified as benign) | P1 | 30 minutes |
| Supabase RLS policy failure — cross-tenant query succeeds | P0 | Immediate |
| Redis stream consumer stops processing (>15 min lag) | P2 | 2 hours |
| Orchestration graph producing unparseable JSON output | P2 | 2 hours |

## Rollback Steps

### Step 1 — Freeze new deployments
```bash
# Block any pending CI/CD pipeline from completing
# In GitHub: Settings → Environments → production → required reviewers (add blocker)
```

### Step 2 — Identify last known-good SHA
```bash
git log --oneline -20
# Find the last commit before the incident
```

### Step 3 — Revert in Git
```bash
git revert HEAD   # for single commit
# OR
git revert <bad-sha>..<HEAD>  # for range

git push origin main
```

### Step 4 — Redeploy Supabase migrations (if schema changed)
```bash
# In Supabase SQL editor: run the previous migration version
# Check: audit-evidence/pipeline-runs/ for last known-good migration SHA
```

### Step 5 — Reload agent prompts
```bash
# Verify the rolled-back prompts/ directory has the correct version
cat prompts/soc1-triage-agent.md | head -5
# Should show version: X.Y.Z matching the known-good SHA
```

### Step 6 — Restart n8n workflows
1. In n8n admin: deactivate affected workflows
2. Wait 30 seconds
3. Reactivate

### Step 7 — Validate rollback
```bash
python3 scripts/prompt_regression_runner.py --validate-only --prompts-dir prompts/
python3 scripts/compliance_gate.py --prompts-dir prompts/ --migrations-dir vakros-soc/agent/
```
Both must pass before declaring rollback complete.

### Step 8 — Write incident postmortem
- Template: `/runbooks/postmortem-template.md`
- File in: `/audit-evidence/` with ISO-8601 date
- Link to GitHub issue

## Post-rollback verification checklist
- [ ] SOC validation loop manual run: all 3 payloads detected
- [ ] HITL gate: manual test confirms escalation fires correctly
- [ ] Supabase: confirm RLS policies active on all tables
- [ ] n8n: SOC validation loop and compliance drift audit workflows active
- [ ] Grafana/monitoring: no active P0/P1 alerts
- [ ] Notify stakeholders: rollback complete, RCA in progress

## Contacts
- Engineering Manager: on-call rotation (PagerDuty)
- Release Manager: on-call rotation
- Supabase admin: Vakros platform admin account
