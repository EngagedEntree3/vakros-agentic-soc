import { NextResponse } from 'next/server'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_KEY!
)

export async function GET() {
  const [alertsRes, actionsRes] = await Promise.all([
    supabase.from('alerts').select('status, triage_verdict, severity, occurred_at'),
    supabase.from('agent_actions').select('created_at').order('created_at', { ascending: false }).limit(100),
  ])

  const alerts = alertsRes.data ?? []
  const actions = actionsRes.data ?? []

  const total       = alerts.length
  const open        = alerts.filter(a => a.status === 'open').length
  const critical    = alerts.filter(a => (a.severity ?? 0) >= 13 && a.status === 'open').length
  const triaged     = alerts.filter(a => a.triage_verdict).length
  const truePos     = alerts.filter(a => a.triage_verdict === 'true_positive').length
  const triageRate  = total ? Math.round((triaged / total) * 100) : 0
  const actionsLast = actions.length

  return NextResponse.json({
    total, open, critical, triaged, truePos, triageRate, actionsLast
  })
}
