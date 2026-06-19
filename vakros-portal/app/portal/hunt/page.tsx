'use client'
import { useEffect, useState } from 'react'
import { createClient, HuntFinding } from '@/lib/supabase'
import { Search, AlertOctagon, ExternalLink } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export default function HuntPage() {
  const [findings, setFindings] = useState<HuntFinding[]>([])
  const [loading, setLoading]   = useState(true)
  const supabase = createClient()

  useEffect(() => {
    supabase.from('hunt_findings').select('*').order('created_at', { ascending: false })
      .then(({ data }) => { setFindings(data ?? []); setLoading(false) })
  }, [])

  const sevColor = (s: number | null) =>
    (s ?? 0) >= 13 ? 'text-red-400 bg-red-900/30 border-red-800/50' :
    (s ?? 0) >= 10 ? 'text-orange-400 bg-orange-900/30 border-orange-800/50' :
    'text-yellow-400 bg-yellow-900/20 border-yellow-800/40'

  return (
    <div className="p-6 max-w-4xl">
      <div className="mb-6">
        <h1 className="text-lg font-semibold text-white">Threat Hunt Findings</h1>
        <p className="text-xs text-slate-400 mt-0.5">Proactive AI-driven threat hunting results</p>
      </div>

      {loading && <p className="text-slate-500 text-sm">Loading…</p>}

      {!loading && findings.length === 0 && (
        <div className="bg-[#111827] border border-slate-700/60 rounded-xl p-12 text-center">
          <Search size={28} className="mx-auto mb-3 text-slate-600" />
          <p className="text-slate-400 font-medium">No hunt findings yet</p>
          <p className="text-slate-500 text-sm mt-1">Run <code className="text-blue-400">python hunt_runner.py --all</code> to start hunting</p>
        </div>
      )}

      <div className="space-y-4">
        {findings.map(f => (
          <div key={f.id} className="bg-[#111827] border border-slate-700/60 rounded-xl p-5">
            <div className="flex items-start justify-between gap-4 mb-3">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <AlertOctagon size={14} className="text-red-400 shrink-0" />
                  <h3 className="text-sm font-semibold text-white">{f.title}</h3>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full border ${sevColor(f.severity)}`}>
                    SEV {f.severity}
                  </span>
                  <span className="text-xs text-slate-500">{f.hypothesis}</span>
                  <span className="text-xs text-slate-500">{formatDistanceToNow(new Date(f.created_at), { addSuffix: true })}</span>
                </div>
              </div>
              <span className={`text-xs px-2 py-1 rounded-lg border ${
                f.status === 'open' ? 'bg-red-900/30 border-red-700/50 text-red-300' :
                f.status === 'resolved' ? 'bg-green-900/30 border-green-700/50 text-green-300' :
                'bg-slate-700 border-slate-600 text-slate-300'
              }`}>{f.status}</span>
            </div>

            <p className="text-sm text-slate-300 mb-3">{f.summary}</p>

            {f.affected_hosts && f.affected_hosts.length > 0 && (
              <div className="mb-2">
                <p className="text-xs text-slate-500 mb-1.5">Affected hosts</p>
                <div className="flex flex-wrap gap-1.5">
                  {f.affected_hosts.map(h => (
                    <span key={h} className="text-xs px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300 font-mono">{h}</span>
                  ))}
                </div>
              </div>
            )}

            {f.mitre_techniques && f.mitre_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {f.mitre_techniques.map(t => (
                  <a key={t} href={`https://attack.mitre.org/techniques/${t}`} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1 text-xs px-2 py-0.5 bg-purple-900/30 border border-purple-700/40 text-purple-300 rounded hover:bg-purple-900/50 transition-colors">
                    {t} <ExternalLink size={9} />
                  </a>
                ))}
              </div>
            )}

            {f.confidence && (
              <div className="mt-3 flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 rounded-full" style={{ width: `${Math.round(f.confidence * 100)}%` }} />
                </div>
                <span className="text-xs text-slate-400">{Math.round(f.confidence * 100)}% confidence</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
