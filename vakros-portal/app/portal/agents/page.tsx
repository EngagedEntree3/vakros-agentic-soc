'use client'
import { useEffect, useState } from 'react'
import { createClient } from '@/lib/supabase'
import { Server, Wifi, WifiOff } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

type Agent = { id: string; name: string; os: string | null; status: string | null; last_keepalive: string | null }

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)
  const supabase = createClient()

  useEffect(() => {
    supabase.from('agents').select('*').order('name')
      .then(({ data }) => { setAgents(data ?? []); setLoading(false) })
  }, [])

  const online  = agents.filter(a => a.status === 'active').length
  const offline = agents.filter(a => a.status !== 'active').length

  return (
    <div className="p-6 max-w-4xl">
      <div className="mb-5">
        <h1 className="text-lg font-semibold text-white">Monitored Agents</h1>
        <p className="text-xs text-slate-400 mt-0.5">{online} online · {offline} offline</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {loading && <p className="text-slate-500 text-sm col-span-3">Loading…</p>}
        {agents.map(a => (
          <div key={a.id} className="bg-[#111827] border border-slate-700/60 rounded-xl p-4 hover:border-slate-600/60 transition-colors">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <Server size={13} className="text-slate-400 shrink-0" />
                <span className="text-sm font-medium text-white truncate">{a.name}</span>
              </div>
              {a.status === 'active'
                ? <Wifi size={13} className="text-green-400 shrink-0" />
                : <WifiOff size={13} className="text-slate-600 shrink-0" />}
            </div>
            <p className="text-xs text-slate-500 font-mono mb-1">{a.id}</p>
            <p className="text-xs text-slate-500">{a.os ?? 'Unknown OS'}</p>
            {a.last_keepalive && (
              <p className="text-xs text-slate-600 mt-1.5">
                Last seen {formatDistanceToNow(new Date(a.last_keepalive), { addSuffix: true })}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
