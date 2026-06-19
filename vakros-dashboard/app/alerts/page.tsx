'use client'
import { useEffect, useState } from 'react'
import { supabase, Alert } from '@/lib/supabase'
import Link from 'next/link'
import { ArrowLeft, RefreshCw } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      const { data } = await supabase
        .from('alerts')
        .select('*')
        .order('occurred_at', { ascending: false })
        .limit(500)
      setAlerts(data ?? [])
      setLoading(false)
    }
    load()
  }, [])

  const filtered = alerts.filter(a =>
    !search ||
    (a.rule_desc ?? '').toLowerCase().includes(search.toLowerCase()) ||
    (a.agent_id ?? '').toLowerCase().includes(search.toLowerCase()) ||
    (a.event_type ?? '').toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-white p-6">
      <div className="max-w-screen-xl mx-auto">
        <div className="flex items-center gap-4 mb-6">
          <Link href="/" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors text-sm">
            <ArrowLeft size={14} /> Dashboard
          </Link>
          <h1 className="text-lg font-semibold">All Alerts</h1>
          <span className="text-xs text-slate-500">{filtered.length} results</span>
        </div>
        <input
          type="text"
          placeholder="Search by rule, host, or event type..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-full mb-4 px-4 py-2.5 bg-[#111827] border border-slate-700/60 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/60"
        />
        {loading ? (
          <div className="flex items-center justify-center h-40 text-slate-500">
            <RefreshCw size={20} className="animate-spin mr-2" /> Loading...
          </div>
        ) : (
          <div className="space-y-1">
            {filtered.map(a => (
              <div key={a.id} className="flex items-center gap-4 px-4 py-3 bg-[#111827] border border-slate-700/40 rounded-lg hover:border-slate-600/60 transition-colors text-xs">
                <span className={`font-bold w-6 text-center ${
                  (a.severity ?? 0) >= 13 ? 'text-red-400' :
                  (a.severity ?? 0) >= 10 ? 'text-orange-400' :
                  (a.severity ?? 0) >= 7  ? 'text-yellow-400' : 'text-green-400'
                }`}>{a.severity}</span>
                <span className="text-slate-300 flex-1 truncate">{a.rule_desc}</span>
                <span className="text-slate-500 font-mono">{a.agent_id}</span>
                <span className="text-slate-500">{a.event_type?.replace(/_/g, ' ')}</span>
                <span className={`px-2 py-0.5 rounded-full text-xs ${
                  a.triage_verdict === 'true_positive' ? 'bg-red-900/50 text-red-300' :
                  a.triage_verdict === 'false_positive' ? 'bg-green-900/50 text-green-300' :
                  a.triage_verdict ? 'bg-blue-900/50 text-blue-300' :
                  'bg-slate-700 text-slate-400'
                }`}>{a.triage_verdict ?? 'untriaged'}</span>
                <span className="text-slate-600">{formatDistanceToNow(new Date(a.occurred_at), { addSuffix: true })}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
