'use client'
import { useEffect, useState } from 'react'
import { createClient, Alert } from '@/lib/supabase'
import { RefreshCw } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

const SEV_COLOR = (s: number | null) =>
  (s ?? 0) >= 13 ? 'text-red-400' : (s ?? 0) >= 10 ? 'text-orange-400' :
  (s ?? 0) >= 7  ? 'text-yellow-400' : 'text-green-400'

export default function AlertsPage() {
  const [alerts, setAlerts]   = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState<'all'|'open'|'critical'>('all')
  const [search, setSearch]   = useState('')
  const supabase = createClient()

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      const { data } = await supabase.from('alerts').select('*')
        .order('severity', { ascending: false })
        .order('occurred_at', { ascending: false })
        .limit(300)
      setAlerts(data ?? [])
      setLoading(false)
    }
    load()
  }, [])

  const filtered = alerts.filter(a => {
    if (filter === 'open' && a.status !== 'open') return false
    if (filter === 'critical' && (a.severity ?? 0) < 13) return false
    if (search && !(`${a.rule_desc} ${a.agent_id} ${a.event_type}`).toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  return (
    <div className="p-6 max-w-5xl">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-lg font-semibold text-white">Alerts</h1>
          <p className="text-xs text-slate-400 mt-0.5">{filtered.length} results</p>
        </div>
        <div className="flex items-center gap-2">
          {(['all','open','critical'] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${
                filter === f ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700/60'
              }`}>{f}</button>
          ))}
        </div>
      </div>

      <input type="text" placeholder="Search alerts…" value={search}
        onChange={e => setSearch(e.target.value)}
        className="w-full mb-4 px-4 py-2.5 bg-[#111827] border border-slate-700/60 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/60" />

      <div className="bg-[#111827] border border-slate-700/60 rounded-xl overflow-hidden">
        {loading && <div className="flex items-center justify-center py-16 text-slate-500"><RefreshCw size={18} className="animate-spin mr-2" /> Loading…</div>}
        <table className="w-full text-xs">
          <thead className="border-b border-slate-700/60">
            <tr>{['Sev','Rule','Host','Event Type','Time','Verdict'].map(h => (
              <th key={h} className="px-4 py-3 text-left text-slate-500 font-medium uppercase tracking-wider">{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {filtered.map(a => (
              <tr key={a.id} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                <td className="px-4 py-3"><span className={`font-bold ${SEV_COLOR(a.severity)}`}>{a.severity}</span></td>
                <td className="px-4 py-3 max-w-xs"><p className="text-slate-200 truncate">{a.rule_desc}</p></td>
                <td className="px-4 py-3 font-mono text-slate-400">{a.agent_id}</td>
                <td className="px-4 py-3 text-slate-400">{a.event_type?.replace(/_/g,' ')}</td>
                <td className="px-4 py-3 text-slate-500 whitespace-nowrap">{formatDistanceToNow(new Date(a.occurred_at), { addSuffix: true })}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded-full text-xs ${
                    a.triage_verdict === 'true_positive'  ? 'bg-red-900/50 text-red-300' :
                    a.triage_verdict === 'false_positive' ? 'bg-green-900/50 text-green-300' :
                    a.triage_verdict ? 'bg-blue-900/50 text-blue-300' : 'bg-slate-700 text-slate-400'
                  }`}>{a.triage_verdict ?? 'pending'}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
