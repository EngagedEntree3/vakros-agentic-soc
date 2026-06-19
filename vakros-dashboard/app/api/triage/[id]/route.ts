import { NextRequest, NextResponse } from 'next/server'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_KEY!
)

export async function POST(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const alertId = params.id

  // Fetch the alert
  const { data: alert, error: fetchErr } = await supabase
    .from('alerts')
    .select('*')
    .eq('id', alertId)
    .single()

  if (fetchErr || !alert) {
    return NextResponse.json({ error: 'Alert not found' }, { status: 404 })
  }

  // Check env
  const anthropicKey = process.env.ANTHROPIC_API_KEY
  if (!anthropicKey) {
    return NextResponse.json({
      error: 'ANTHROPIC_API_KEY not configured. Add it to .env.local and restart.'
    }, { status: 503 })
  }

  try {
    // Dynamic import — only pulls in the agent when called
    const Anthropic = (await import('@anthropic-ai/sdk')).default
    const client = new Anthropic({ apiKey: anthropicKey })

    const TOOL_DEFINITIONS = [
      {
        name: 'update_alert_triage',
        description: 'Write triage verdict and summary to the alert record',
        input_schema: {
          type: 'object' as const,
          properties: {
            alert_id: { type: 'string' },
            verdict: { type: 'string', enum: ['true_positive', 'false_positive', 'benign', 'needs_investigation'] },
            confidence: { type: 'number', minimum: 0, maximum: 1 },
            summary: { type: 'string' },
            recommended_actions: { type: 'array', items: { type: 'string' } },
            mitre_techniques: { type: 'array', items: { type: 'string' } },
          },
          required: ['alert_id', 'verdict', 'confidence', 'summary'],
        },
      },
    ]

    const systemPrompt = `You are an expert SOC analyst. Analyze the security alert and call update_alert_triage with your verdict.

Verdict options:
- true_positive: confirmed real attack or breach
- false_positive: confirmed normal/benign activity incorrectly flagged  
- benign: low-risk, expected behavior
- needs_investigation: insufficient data, needs human review

Severity scale: 1-6 low, 7-10 medium, 11-12 high, 13-15 critical.
Be concise in summary (2-3 sentences max). Always call the tool.`

    const userMsg = `Triage this alert:
ID: ${alert.id}
Rule: ${alert.rule_desc}
Severity: ${alert.severity}/15
Event Type: ${alert.event_type}
Host/Agent: ${alert.agent_id}
Platform: ${alert.source_platform}
Time: ${alert.occurred_at}
Threat Intel: ${JSON.stringify(alert.threat_intel ?? {})}
Raw Data: ${JSON.stringify(alert.raw_event ?? {})}`

    const messages: any[] = [{ role: 'user', content: userMsg }]
    let verdict = null
    let confidence = null
    let summary = null

    for (let i = 0; i < 6; i++) {
      const response = await client.messages.create({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        system: systemPrompt,
        tools: TOOL_DEFINITIONS,
        messages,
      })

      messages.push({ role: 'assistant', content: response.content })

      if (response.stop_reason === 'tool_use') {
        const toolUse = response.content.find((b: any) => b.type === 'tool_use') as any
        if (toolUse && toolUse.name === 'update_alert_triage') {
          const input = toolUse.input as any
          verdict    = input.verdict
          confidence = input.confidence
          summary    = input.summary

          // Write to DB
          const triageResult = {
            verdict,
            confidence,
            summary,
            recommended_actions: input.recommended_actions ?? [],
            mitre_techniques:    input.mitre_techniques ?? [],
            triaged_by: 'vakros-api',
            triaged_at: new Date().toISOString(),
          }

          await supabase.from('alerts').update({
            triage_verdict:    verdict,
            triage_confidence: confidence,
            triage_summary:    summary,
            triage_result:     triageResult,
            status: verdict === 'true_positive' ? 'in_progress' : 'closed',
          }).eq('id', alertId)

          // Log agent action
          await supabase.from('agent_actions').insert({
            alert_id:    alertId,
            action_type: 'triage',
            action_data: triageResult,
            performed_by: 'vakros-api',
          }).select()

          messages.push({
            role: 'user',
            content: [{ type: 'tool_result', tool_use_id: toolUse.id, content: 'Triage saved.' }],
          })
          break
        }
      }

      if (response.stop_reason === 'end_turn') break
    }

    return NextResponse.json({ verdict, confidence, summary, alertId })
  } catch (err: any) {
    console.error('Triage error:', err)
    return NextResponse.json({ error: err.message ?? 'Agent error' }, { status: 500 })
  }
}
