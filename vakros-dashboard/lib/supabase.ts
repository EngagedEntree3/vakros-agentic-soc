import { createClient } from '@supabase/supabase-js'

const url  = process.env.NEXT_PUBLIC_SUPABASE_URL!
const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

export const supabase = createClient(url, anon, {
  realtime: { params: { eventsPerSecond: 10 } }
})

export type Alert = {
  id: string
  wazuh_alert_id: string
  agent_id: string | null
  rule_id: number | null
  rule_desc: string | null
  severity: number | null
  occurred_at: string
  triage_verdict: string | null
  triage_confidence: number | null
  triage_summary: string | null
  status: string | null
  source_platform: string | null
  event_type: string | null
  threat_intel: Record<string, unknown> | null
  triage_result: Record<string, unknown> | null
  needs_retriage: boolean | null
  created_at: string
}

export type Agent = {
  id: string
  name: string
  os: string | null
  status: string | null
  last_keepalive: string | null
}
