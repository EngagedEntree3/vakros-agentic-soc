'use client'
import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { createClient } from '@/lib/supabase'
import Link from 'next/link'
import {
  Shield, LayoutDashboard, AlertTriangle, Search,
  Server, LogOut, ChevronRight, User
} from 'lucide-react'

const NAV = [
  { href: '/portal',         label: 'Dashboard',    icon: LayoutDashboard },
  { href: '/portal/alerts',  label: 'Alerts',       icon: AlertTriangle },
  { href: '/portal/hunt',    label: 'Threat Hunts', icon: Search },
  { href: '/portal/agents',  label: 'Agents',       icon: Server },
]

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  const router   = useRouter()
  const pathname = usePathname()
  const supabase = createClient()
  const [email, setEmail]   = useState('')
  const [tenant, setTenant] = useState('')

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      if (!data.user) { router.push('/auth/login'); return }
      setEmail(data.user.email ?? '')
    })
    supabase.from('tenants').select('name').single().then(({ data }) => {
      if (data) setTenant(data.name)
    })
  }, [])

  const signOut = async () => {
    await supabase.auth.signOut()
    router.push('/auth/login')
  }

  return (
    <div className="min-h-screen bg-[#0a0e1a] flex">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 border-r border-slate-700/60 bg-[#0d1121] flex flex-col">
        {/* Logo */}
        <div className="px-5 py-5 border-b border-slate-700/60">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
              <Shield size={15} className="text-white" />
            </div>
            <div>
              <p className="font-bold text-white text-sm tracking-tight">VAKROS</p>
              <p className="text-xs text-slate-500 truncate max-w-[110px]">{tenant || 'Portal'}</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || (href !== '/portal' && pathname.startsWith(href))
            return (
              <Link key={href} href={href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  active
                    ? 'bg-blue-600/20 text-blue-300 border border-blue-600/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-700/40'
                }`}>
                <Icon size={15} />
                {label}
                {active && <ChevronRight size={12} className="ml-auto opacity-60" />}
              </Link>
            )
          })}
        </nav>

        {/* User */}
        <div className="px-3 py-4 border-t border-slate-700/60">
          <div className="flex items-center gap-2.5 px-3 py-2 mb-1">
            <div className="w-7 h-7 rounded-full bg-slate-700 flex items-center justify-center">
              <User size={13} className="text-slate-400" />
            </div>
            <p className="text-xs text-slate-400 truncate flex-1">{email}</p>
          </div>
          <button onClick={signOut}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs text-slate-500 hover:text-red-400 hover:bg-red-900/20 transition-colors">
            <LogOut size={13} />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}
