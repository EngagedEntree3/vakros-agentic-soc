'use client'
import { useState } from 'react'
import { createClient } from '@/lib/supabase'
import { Shield, Loader2 } from 'lucide-react'

export default function LoginPage() {
  const [email, setEmail]     = useState('')
  const [sent, setSent]       = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const supabase = createClient()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true); setError('')
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: { emailRedirectTo: `${window.location.origin}/auth/callback` },
    })
    if (error) setError(error.message)
    else setSent(true)
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-[#0a0e1a] flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center">
            <Shield size={20} className="text-white" />
          </div>
          <div>
            <p className="font-bold text-white text-lg tracking-tight">VAKROS</p>
            <p className="text-xs text-slate-400">Customer Portal</p>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-700/60 rounded-2xl p-8">
          {sent ? (
            <div className="text-center">
              <div className="w-12 h-12 rounded-full bg-green-900/40 border border-green-700/50 flex items-center justify-center mx-auto mb-4">
                <Shield size={20} className="text-green-400" />
              </div>
              <h2 className="text-white font-semibold mb-2">Check your email</h2>
              <p className="text-sm text-slate-400">We sent a magic link to <strong className="text-slate-200">{email}</strong>. Click it to sign in.</p>
            </div>
          ) : (
            <>
              <h1 className="text-lg font-semibold text-white mb-1">Sign in</h1>
              <p className="text-sm text-slate-400 mb-6">Enter your work email to receive a magic link.</p>
              <form onSubmit={handleLogin} className="space-y-4">
                <input
                  type="email"
                  required
                  placeholder="you@company.com"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700/60 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/60"
                />
                {error && <p className="text-xs text-red-400">{error}</p>}
                <button
                  type="submit"
                  disabled={loading || !email}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {loading ? <Loader2 size={14} className="animate-spin" /> : null}
                  {loading ? 'Sending…' : 'Send magic link'}
                </button>
              </form>
            </>
          )}
        </div>

        <p className="text-xs text-center text-slate-600 mt-6">
          Secured by Vakros Agentic SOC · Powered by Anthropic
        </p>
      </div>
    </div>
  )
}
