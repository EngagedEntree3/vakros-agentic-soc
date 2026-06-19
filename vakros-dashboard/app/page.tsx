'use client'

import { useEffect, useState, useCallback } from 'react'
import { supabase, Alert } from '@/lib/supabase'
import {
  Shield, AlertTriangle, CheckCircle2, Clock, Activity,
  ChevronRight, RefreshCw, Zap, Eye, X, ExternalLink,
  Terminal, Target, Server, TrendingUp, AlertOctagon
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts'

// ── Helpers ──────────────────────────────────────────────────────────────────

function sevColor(s: number | null) {
  if (!s) return 'text-slate-500'
  if (s >= 13) return 'text-red-400'
  if (s >= 10) return 'text-orange-400'
  if (s >= 7)  return 'text-yellow-400'
  return 'text-green-400'
}

function sevBg(s: number | null) {
  if (!s) return 'bg-slate-800'
  if (s >= 13) return 'bg-red-900/40 border border-red-800/60'
  if (s >= 10) return 'bg-orange-900/40 border border-orange-800/60'
  if (s >= 7)  return 'bg-yellow-900/30 border border-yellow-800/50'
  return 'bg-green-900/30 border border-green-800/50'
}

function verdictBadge(v: string | null) {
  if (!v) return <span className="text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-400">Untriaged</span>
  const map: Record<string, string> = {
    true_positive: 'bg-red-900/60 text-red-300 border border-red-700/50',
    false_positive: 'bg-green-900/60 text-green-300 border border-green-700/50',
    benign: 'bg-blue-900/60 text-blue-300 border border-blue-700/50',
    needs_investigation: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
  }
  const labels: Record<string, string> = {
    true_positive: 'True Positive',
    false_positive: 'False Positive',
    benign: 'Benign',
    needs_investigation: 'Investigate',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full ${map[v] ?? 'bg-slate-700 text-slate-400'}`}>
      {labels[v] ?? v}
    </span>
  )
}

function statusDot(s: string | null) {
  const map: Record<string, string> = {
    open: 'bg-red-400',
    in_progress: 'bg-yellow-400',
    closed: 'bg-green-400',
  }
  return <span className={`inline-block w-2 h-2 rounded-full pulse-dot ${map[s ?? 'open'] ?? 'bg-slate-500'}`} />
}

// ── Alert Detail Panel ────────────────────────────────────────────────────────

function AlertDetail({ alert, onClose, onTriage }: {
  alert: Alert
  onClose: () => void
  onTriage: (id: string) => void
}) {
  const [triaging, setTriaging] = useState(false)
  const [triageMsg, setTriageMsg] = useState('')

  const handleTriage = async () => {
    setTriaging(true)
    setTriageMsg('Agent running...')
    try {
      const res = await fetch(`/api/triage/${alert.id}`, { method: 'POST' })
      const data = await res.json()
      if (data.error) {
        setTriageMsg(`Error: ${data.error}`)
      } else {
        setTriageMsg(`✓ ${data.verdict ?? 'Done'} (${Math.round((data.confidence ?? 0) * 100)}% confidence)`)
        onTriage(alert.id)
      }
    } catch (e) {
      setTriageMsg('Network error')
    } finally {
      setTriaging(false)
    }
  }

  const ti = alert.threat_intel as Record<string, unknown> | null

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-xl h-full bg-[#111827] border-l border-slate-700/60 overflow-y-auto shadow-2xl">

        {/* Header */}
        <div className="sticky top-0 bg-[#111827] border-b border-slate-700/60 px-5 py-4 flex items-start justify-between z-10">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              {statusDot(alert.status)}
              <span className="text-xs text-slate-400 uppercase tracking-wider">{alert.source_platform ?? 'wazuh'}</span>
              <span className="text-xs text-slate-500">·</span>
              <span className={`text-xs font-bold ${sevColor(alert.severity)}`}>SEV {alert.severity}/15</span>
            </div>
            <h2 className="text-sm font-semibold text-white leading-tight">{alert.rule_desc ?? 'Unknown Alert'}</h2>
            <p className="text-xs text-slate-400 mt-1">{alert.agent_id} · {formatDistanceToNow(new Date(alert.occurred_at), { addSuffix: true })}</p>
          </div>
          <button onClick={onClose} className="ml-3 p-1.5 rounded hover:bg-slate-700 transition-colors">
            <X size={16} />
          </button>
        </div>

        <div className="p-5 space-y-5">

          {/* Triage Action */}
          {!alert.triage_verdict ? (
            <div className="rounded-lg bg-blue-950/40 border border-blue-800/50 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-blue-300">Alert not yet triaged</p>
                  <p className="text-xs text-blue-400/70 mt-0.5">AI agent will analyze and write verdict to DB</p>
                </div>
                <button
                  onClick={handleTriage}
                  disabled={triaging}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
                >
                  <Zap size={14} className={triaging ? 'animate-spin' : ''} />
                  {triaging ? 'Running...' : 'Triage Now'}
                </button>
              </div>
              {triageMsg && <p className="mt-2 text-xs text-blue-300">{triageMsg}</p>}
            </div>
          ) : (
            <div className={`rounded-lg p-4 ${
              alert.triage_verdict === 'true_positive' ? 'bg-red-950/40 border border-red-800/50' :
              alert.triage_verdict === 'false_positive' ? 'bg-green-950/40 border border-green-800/50' :
              'bg-slate-800/60 border border-slate-700/60'
            }`}>
              <div className="flex items-center justify-between mb-2">
                {verdictBadge(alert.triage_verdict)}
                {alert.triage_confidence && (
                  <span className="text-xs text-slate-400">{Math.round(alert.triage_confidence * 100)}% confidence</span>
                )}
              </div>
              {alert.triage_summary && (
                <p className="text-xs text-slate-300 leading-relaxed">{alert.triage_summary}</p>
              )}
              <button
                onClick={handleTriage}
                disabled={triaging}
                className="mt-3 flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <RefreshCw size={11} className={triaging ? 'animate-spin' : ''} />
                Re-triage
              </button>
            </div>
          )}

          {/* Event Info */}
          <div>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Event Details</h3>
            <div className="space-y-2">
              {[
                ['Alert ID', alert.id.slice(0, 18) + '...'],
                ['Rule', alert.rule_desc],
                ['Event Type', alert.event_type],
                ['Host / Agent', alert.agent_id],
                ['Platform', alert.source_platform],
                ['Status', alert.status],
                ['Occurred', new Date(alert.occurred_at).toLocaleString()],
              ].map(([k, v]) => v && (
                <div key={k as string} className="flex items-start gap-3">
                  <span className="text-xs text-slate-500 w-24 shrink-0">{k}</span>
                  <span className="text-xs text-slate-300 break-all">{v as string}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Intel */}
          {ti && Object.keys(ti).length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Threat Intelligence</h3>
              <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-3 space-y-2">
                {Object.entries(ti).map(([k, v]) => (
                  <div key={k} className="flex items-start gap-3">
                    <span className="text-xs text-slate-500 w-28 shrink-0">{k.replace(/_/g, ' ')}</span>
                    <span className="text-xs text-slate-300 font-mono break-all">
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MITRE Techniques */}
          {alert.triage_result && (alert.triage_result as any).mitre_techniques?.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">MITRE ATT&CK</h3>
              <div className="flex flex-wrap gap-2">
                {((alert.triage_result as any).mitre_techniques as string[]).map((t) => (
                  <a
                    key={t}
                    href={`https://attack.mitre.org/techniques/${t.replace('.', '/').replace('T', 'T')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-xs px-2 py-1 bg-purple-900/40 border border-purple-700/50 text-purple-300 rounded hover:bg-purple-900/60 transition-colors"
                  >
                    {t} <ExternalLink size={10} />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions */}
          {alert.triage_result && (alert.triage_result as any).recommended_actions?.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Recommended Actions</h3>
              <ol className="space-y-2">
                {((alert.triage_result as any).recommended_actions as string[]).map((a, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="text-xs font-bold text-blue-400 mt-0.5 w-4 shrink-0">{i + 1}.</span>
                    <span className="text-xs text-slate-300">{a}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

        </div>
      </div>
    </div>
  )
}

// ── Metric Card ───────────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, icon: Icon, color }: {
  label: string; value: number | string; sub?: string
  icon: React.ElementType; color: string
}) {
  return (
    <div className="bg-[#111827] border border-slate-700/60 rounded-xl p-5 hover:border-slate-600/80 transition-colors">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-400 uppercase tracking-wider mb-1">{label}</p>
          <p className={`text-3xl font-bold ${color}`}>{value}</p>
          {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
        </div>
        <div className={`p-2.5 rounded-lg bg-slate-800`}>
          <Icon size={18} className={color} />
        </div>
      </div>
    </div>
  )
}

// ── Main Dashboard ────────────────────────────────────────────────────────────

const VERDICT_COLORS: Record<string, string> = {
  true_positive: '#ef4444',
  false_positive: '#22c55e',
  benign: '#3b82f6',
  needs_investigation: '#eab308',
  untriaged: '#6b7280',
}

export default function Dashboard() {
  const [alerts, setAlerts]       = useState<Alert[]>([])
  const [loading, setLoading]     = useState(true)
  const [selected, setSelected]   = useState<Alert | null>(null)
  const [filter, setFilter]       = useState<'all' | 'open' | 'critical' | 'untriaged'>('all')
  const [lastRefresh, setLastRefresh] = useState(new Date())

  const loadAlerts = useCallback(async () => {
    setLoading(true)
    const { data } = await supabase
      .from('alerts')
      .select('*')
      .order('severity', { ascending: false })
      .order('occurred_at', { ascending: false })
      .limit(200)
    setAlerts(data ?? [])
    setLastRefresh(new Date())
    setLoading(false)
  }, [])

  useEffect(() => {
    loadAlerts()
    // Real-time subscription
    const channel = supabase
      .channel('alerts-rt')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'alerts' }, () => {
        loadAlerts()
      })
      .subscribe()
    return () => { supabase.removeChannel(channel) }
  }, [loadAlerts])

  // Derived stats
  const total        = alerts.length
  const open         = alerts.filter(a => a.status === 'open').length
  const critical     = alerts.filter(a => (a.severity ?? 0) >= 13 && a.status === 'open').length
  const untriaged    = alerts.filter(a => !a.triage_verdict).length
  const truePositive = alerts.filter(a => a.triage_verdict === 'true_positive').length
  const triaged      = alerts.filter(a => a.triage_verdict).length
  const triageRate   = total ? Math.round((triaged / total) * 100) : 0

  // Verdict pie data
  const verdictGroups = alerts.reduce((acc, a) => {
    const k = a.triage_verdict ?? 'untriaged'
    acc[k] = (acc[k] ?? 0) + 1
    return acc
  }, {} as Record<string, number>)
  const pieData = Object.entries(verdictGroups).map(([name, value]) => ({ name, value }))

  // Severity bar data
  const sevBuckets = [
    { label: 'Low (1-6)',  count: alerts.filter(a => (a.severity ?? 0) <= 6).length,  fill: '#22c55e' },
    { label: 'Med (7-10)', count: alerts.filter(a => (a.severity ?? 0) >= 7 && (a.severity ?? 0) <= 10).length, fill: '#eab308' },
    { label: 'High (11-12)', count: alerts.filter(a => (a.severity ?? 0) >= 11 && (a.severity ?? 0) <= 12).length, fill: '#f97316' },
    { label: 'Crit (13+)', count: alerts.filter(a => (a.severity ?? 0) >= 13).length, fill: '#ef4444' },
  ]

  // Event type bar
  const eventGroups = alerts.reduce((acc, a) => {
    const k = a.event_type ?? 'unknown'
    acc[k] = (acc[k] ?? 0) + 1
    return acc
  }, {} as Record<string, number>)
  const eventData = Object.entries(eventGroups)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' '), count }))

  // Filtered alerts for table
  const filtered = alerts.filter(a => {
    if (filter === 'open')     return a.status === 'open'
    if (filter === 'critical') return (a.severity ?? 0) >= 13 && a.status === 'open'
    if (filter === 'untriaged') return !a.triage_verdict
    return true
  })

  const handleTriageDone = useCallback((id: string) => {
    loadAlerts()
    // Keep panel open so user sees updated verdict
    setTimeout(() => {
      supabase.from('alerts').select('*').eq('id', id).single().then(({ data }) => {
        if (data) setSelected(data)
      })
    }, 1500)
  }, [loadAlerts])

  return (
    <div className="min-h-screen bg-[#0a0e1a]">

      {/* Top Nav */}
      <header className="border-b border-slate-700/60 bg-[#0d1121]/80 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-screen-2xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
              <Shield size={16} className="text-white" />
            </div>
            <div>
              <span className="font-bold text-white tracking-tight">VAKROS</span>
              <span className="ml-2 text-xs text-slate-400 font-medium">SOC PORTAL</span>
            </div>
            <span className="ml-4 text-xs px-2 py-0.5 rounded-full bg-green-900/50 text-green-400 border border-green-700/50 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 pulse-dot" />
              Live
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-slate-500">
              Updated {formatDistanceToNow(lastRefresh, { addSuffix: true })}
            </span>
            <button
              onClick={loadAlerts}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white px-3 py-1.5 rounded-lg hover:bg-slate-700/60 transition-colors"
            >
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-screen-2xl mx-auto px-6 py-6 space-y-6">

        {/* Metrics Row */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
          <MetricCard label="Total Alerts"   value={total}       sub="all time"                icon={Activity}       color="text-slate-300" />
          <MetricCard label="Open"           value={open}        sub="needs attention"         icon={AlertTriangle}  color="text-yellow-400" />
          <MetricCard label="Critical Open"  value={critical}    sub="severity 13+"            icon={AlertOctagon}   color="text-red-400" />
          <MetricCard label="Untriaged"      value={untriaged}   sub="awaiting AI triage"      icon={Clock}          color="text-orange-400" />
          <MetricCard label="True Positives" value={truePositive} sub="confirmed attacks"      icon={Target}         color="text-red-400" />
          <MetricCard label="Triage Rate"    value={`${triageRate}%`} sub={`${triaged}/${total} alerts`} icon={TrendingUp} color="text-blue-400" />
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Severity Distribution */}
          <div className="bg-[#111827] border border-slate-700/60 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={sevBuckets} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sevBuckets.map((b, i) => <Cell key={i} fill={b.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Verdict Pie */}
          <div className="bg-[#111827] border border-slate-700/60 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Triage Verdicts</h3>
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={65}
                    dataKey="value" nameKey="name" paddingAngle={3}>
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={VERDICT_COLORS[entry.name] ?? '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-40 flex items-center justify-center text-slate-500 text-sm">No verdict data</div>
            )}
          </div>

          {/* Top Event Types */}
          <div className="bg-[#111827] border border-slate-700/60 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Top Attack Categories</h3>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={eventData} layout="vertical" margin={{ top: 0, right: 10, left: 10, bottom: 0 }}>
                <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#94a3b8' }} width={100} />
                <Tooltip
                  contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

        </div>

        {/* Alert Table */}
        <div className="bg-[#111827] border border-slate-700/60 rounded-xl overflow-hidden">

          {/* Table Header */}
          <div className="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-white">Alert Queue</h2>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-400">{filtered.length}</span>
            </div>
            <div className="flex items-center gap-2">
              {(['all', 'open', 'critical', 'untriaged'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${
                    filter === f
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-white hover:bg-slate-700/60'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-700/60">
                  {['Status', 'Sev', 'Rule / Alert', 'Host', 'Event Type', 'Time', 'Verdict', 'Action'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-slate-500 font-medium uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-slate-500">
                      <RefreshCw size={20} className="animate-spin mx-auto mb-2" />
                      Loading alerts...
                    </td>
                  </tr>
                )}
                {!loading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-slate-500">
                      <CheckCircle2 size={20} className="mx-auto mb-2 text-green-400" />
                      No alerts matching this filter
                    </td>
                  </tr>
                )}
                {filtered.map(alert => (
                  <tr
                    key={alert.id}
                    className={`alert-row border-b border-slate-800/60 cursor-pointer transition-colors ${
                      selected?.id === alert.id ? 'selected' : ''
                    }`}
                    onClick={() => setSelected(alert)}
                  >
                    <td className="px-4 py-3">
                      {statusDot(alert.status)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-bold ${sevColor(alert.severity)}`}>{alert.severity ?? '?'}</span>
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <p className="text-slate-200 truncate">{alert.rule_desc ?? 'Unknown'}</p>
                      <p className="text-slate-500 font-mono truncate">{alert.id.slice(0, 8)}…</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <Server size={11} className="text-slate-500 shrink-0" />
                        <span className="text-slate-400 font-mono truncate max-w-[100px]">{alert.agent_id ?? '-'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-slate-400">{alert.event_type?.replace(/_/g, ' ') ?? '-'}</span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                      {formatDistanceToNow(new Date(alert.occurred_at), { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3">
                      {verdictBadge(alert.triage_verdict)}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={e => { e.stopPropagation(); setSelected(alert) }}
                        className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        <Eye size={12} />
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </main>

      {/* Alert Detail Panel */}
      {selected && (
        <AlertDetail
          alert={selected}
          onClose={() => setSelected(null)}
          onTriage={handleTriageDone}
        />
      )}

    </div>
  )
}
