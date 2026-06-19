'use client'
import { useEffect, useState } from 'react'
import { createClient, Alert, HuntFinding } from '@/lib/supabase'
import {
  AlertTriangle, Shield, Search, Server,
  TrendingUp, Clock, Target, Activity
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

function Metric({ label, value, sub, icon: Icon, color }: {
  label: string; value: number | string; sub?: string
  icon: React.ElementType; color: string
}) {
  return (
    <div className="bg-[#111827] border border-slate-700/60 rounded-xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
          <p className={`text-3xl font-bold ${color}`}>{value}</p>
          {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
        </div>
        <div className="p-2 rounded-lg bg-slate-800">
          <Icon size={16} className={color} />
        </div>
      </div>
    </div>
  )
}

export default function PortalDashboard() {
  const [alerts, setAlerts]   = useState<Alert[]>([])
  const [findings, setFindings] = useState<HuntFinding[]>([])
  const [loading, setLoading] = useState(true)
  const supabase = createClient()

  useEffect(() => {
    const load = async () => {
      const [ar, fr] = await Promise.all([
        supabase.from('alerts').select('*').order('occurred_at', { ascending: false }).limit(100),
        supabase.from('hunt_findings').select('*').order('created_at', { ascending: false }).limit(10),
      ])
      setAlerts(ar.data ?? [])
      setFindings(fr.data ?? [])
      setLoading(false)
    }
    load()

    // Real-time
    const ch = supabase.channel('portal-rt')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'alerts' }, load)
      .subscribe()
    return () => { supabase.removeChannel(ch) }
  }, [])

  const open     = alerts.filter(a => a.status === 'open').length
  const critical = alerts.filter(a => (a.severity ?? 0) >= 13 && a.status === 'open').length
  const triaged  = alerts.filter(a => a.triage_verdict).length
  const truePos  = alerts.filter(a => a.triage_verdict === 'true_positive').length
  const rate     = alerts.length ? Math.round((triaged / alerts.length) * 100) : 0

  const recent = alerts.slice(0, 8)

  function sevColor(s: number | null) {
    if (!s) return 'text-slate-500'
    if (s >= 13) return 'text-red-400'
    if (s >= 10) return 'text-orange-400'
    if (s >= 7)  return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <div>
        <h1 className="text-lg font-semibold text-white">Security Overview</h1>
        <p className="text-sm text-slate-400 mt-0.5">Real-time view of your security posture</p>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <Metric label="Total Alerts"   value={alerts.length}   icon={Activity}       color="text-slate-300" />
        <Metric label="Open"           value={open}            icon={AlertTriangle}  color="text-yellow-400" />
        <Metric label="Critical"       value={critical}        icon={Target}         color="text-red-400" />
        <Metric label="True Positives" value={truePos}         icon={Shield}         color="text-red-400" />
        <Metric label="Triage Rate"    value={`${rate}%`}      icon={TrendingUp}     color="text-blue-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* Recent alerts */}
        <div className="bg-[#111827] border border-slate-700/60 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Recent Alerts</h2>
            <a href="/portal/alerts" className="text-xs text-blue-400 hover:text-blue-300">View all →</a>
          </div>
          <div className="divide-y divide-slate-800/60">
            {loading && <p className="px-5 py-8 text-center text-slate-500 text-sm">Loading…</p>}
            {recent.map(a => (
              <div key={a.id} className="flex items-center gap-3 px-5 py-3 hover:bg-slate-800/30 transition-colors">
                <span className={`text-xs font-bold w-5 text-center ${sevColor(a.severity)}`}>{a.severity}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-slate-200 truncate">{a.rule_desc}</p>
                  <p className="text-xs text-slate-500">{a.agent_id}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${
                  a.triage_verdict === 'true_positive' ? 'bg-red-900/50 text-red-300' :
                  a.triage_verdict === 'false_positive' ? 'bg-green-900/50 text-green-300' :
                  a.triage_verdict ? 'bg-blue-900/50 text-blue-300' :
                  'bg-slate-700 text-slate-400'
                }`}>{a.triage_verdict ?? 'pending'}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Hunt findings */}
        <div className="bg-[#111827] border border-slate-700/60 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Threat Hunt Findings</h2>
            <a href="/portal/hunt" className="text-xs text-blue-400 hover:text-blue-300">View all →</a>
          </div>
          <div className="divide-y divide-slate-800/60">
            {findings.length === 0 && !loading && (
              <div className="px-5 py-8 text-center">
                <Search size={20} className="mx-auto mb-2 text-slate-600" />
                <p className="text-xs text-slate-500">No hunt findings yet</p>
              </div>
            )}
            {findings.map(f => (
              <div key={f.id} className="px-5 py-3">
                <div className="flex items-start justify-between gap-2">
                  <p className="text-xs text-slate-200 font-medium">{f.title}</p>
                  <span className={`text-xs font-bold shrink-0 ${
                    (f.severity ?? 0) >= 13 ? 'text-red-400' :
                    (f.severity ?? 0) >= 10 ? 'text-orange-400' : 'text-yellow-400'
                  }`}>SEV {f.severity}</span>
                </div>
                <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{f.summary}</p>
                <p className="text-xs text-slate-600 mt-1">{formatDistanceToNow(new Date(f.created_at), { addSuffix: true })}</p>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  )
}
