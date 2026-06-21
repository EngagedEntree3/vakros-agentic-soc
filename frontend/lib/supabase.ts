import { createBrowserClient } from '@supabase/ssr'

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}

export type Alert = {
  id: string; wazuh_alert_id: string; agent_id: string | null
  rule_desc: string | null; severity: number | null; occurred_at: string
  triage_verdict: string | null; triage_confidence: number | null
  triage_summary: string | null; status: string | null
  event_type: string | null; threat_intel: Record<string, unknown> | null
}

export type HuntFinding = {
  id: string; title: string; hypothesis: string | null
  severity: number | null; confidence: number | null
  summary: string | null; affected_hosts: string[] | null
  mitre_techniques: string[] | null; status: string; created_at: string
}

export type Tenant = { id: string; name: string; slug: string; plan: string }
