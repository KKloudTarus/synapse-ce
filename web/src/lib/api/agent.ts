import type {
  AgentDecision,
  AgentMessage,
  AgentPlan,
  AgentReadiness,
  AgentSession,
  PendingApproval,
} from '../types'
import { ApiError, getToken, getOnUnauthorized, req } from './client'

function mapAgentSession(r: any): AgentSession {
  return {
    id: r.ID ?? '',
    engagementId: r.EngagementID ?? '',
    initiatedBy: r.InitiatedBy ?? '',
    goal: r.Goal ?? '',
    model: r.Model ?? '',
    status: r.Status ?? '',
    steps: r.Steps ?? 0,
    tokensUsed: r.TokensUsed ?? 0,
    createdAt: r.CreatedAt ?? null,
    updatedAt: r.UpdatedAt ?? null,
  }
}

function mapAgentMessage(r: any): AgentMessage {
  return {
    role: r.role ?? '',
    content: r.content ?? '',
    toolCalls: (r.tool_calls ?? []).map((c: any) => ({ id: c.id ?? '', name: c.name ?? '' })),
    toolCallId: r.tool_call_id ?? '',
  }
}

function mapProposedAction(r: any): PendingApproval {
  return {
    id: r.ID ?? '',
    sessionId: r.SessionID ?? '',
    tool: r.Tool ?? '',
    action: r.Action ?? '',
    target: r.Target?.Value ?? '',
    argv: r.Argv ?? [],
    egressPreview: r.EgressPreview ?? [],
    risk: r.Risk ?? '',
    rationale: r.Rationale ?? '',
  }
}

// AgentStreamEvent is one transcript message (or the terminal marker) on the session stream.
export interface AgentStreamEvent {
  id: number
  message?: AgentMessage
  done?: boolean
  status?: string
}

export async function streamAgentSession(
  engagementId: string,
  sessionId: string,
  opts: { lastEventId?: number; signal?: AbortSignal; onEvent: (e: AgentStreamEvent) => void },
): Promise<void> {
  const id = encodeURIComponent(engagementId)
  const sid = encodeURIComponent(sessionId)
  const qs = opts.lastEventId ? `?lastEventId=${opts.lastEventId}` : ''
  const token = getToken()
  const onUnauthorized = getOnUnauthorized()
  const res = await fetch(`/api/v1/engagements/${id}/agent/sessions/${sid}/stream${qs}`, {
    headers: token ? { authorization: `Bearer ${token}`, accept: 'text/event-stream' } : { accept: 'text/event-stream' },
    signal: opts.signal,
  })
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok || !res.body) throw new ApiError(res.status, `agent stream HTTP ${res.status}`)

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += decoder.decode(value, { stream: true })
    let sep
    while ((sep = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, sep)
      buf = buf.slice(sep + 2)
      let evId = 0
      let event = ''
      let data = ''
      for (const ln of frame.split('\n')) {
        if (ln.startsWith('id:')) evId = parseInt(ln.slice(3).trim(), 10) || 0
        else if (ln.startsWith('event:')) event = ln.slice(6).trim()
        else if (ln.startsWith('data:')) data += ln.slice(5).trim()
      }
      if (event === 'done') {
        let status = ''
        try {
          status = (JSON.parse(data) as { status?: string }).status ?? ''
        } catch {
          /* ignore */
        }
        opts.onEvent({ id: evId, done: true, status })
        return
      }
      try {
        opts.onEvent({ id: evId, message: mapAgentMessage(JSON.parse(data)) })
      } catch {
        /* keep-alive / non-JSON frame */
      }
    }
  }
}

export const agentApi = {
  agentReadiness: async (engagementId: string): Promise<AgentReadiness | null> => {
    try {
      return (await req(`/engagements/${encodeURIComponent(engagementId)}/agent/readiness`)) as AgentReadiness
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },

  startAgentSession: async (engagementId: string, goal: string): Promise<AgentSession> =>
    mapAgentSession(
      await req(`/engagements/${encodeURIComponent(engagementId)}/agent/sessions`, {
        method: 'POST',
        body: JSON.stringify({ goal }),
      }),
    ),

  agentSessions: async (engagementId: string): Promise<AgentSession[]> =>
    ((await req(`/engagements/${encodeURIComponent(engagementId)}/agent/sessions`)) ?? []).map(mapAgentSession),

  agentSession: async (
    engagementId: string,
    sessionId: string,
  ): Promise<{ session: AgentSession; transcript: AgentMessage[] }> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/agent/sessions/${encodeURIComponent(sessionId)}`)
    return { session: mapAgentSession(r.session), transcript: (r.transcript ?? []).map(mapAgentMessage) }
  },

  agentApprovals: async (engagementId: string): Promise<PendingApproval[]> =>
    ((await req(`/engagements/${encodeURIComponent(engagementId)}/agent/approvals`)) ?? []).map(mapProposedAction),

  agentDecisions: async (engagementId: string, sessionId: string): Promise<AgentDecision[]> => {
    const r = await req(
      `/engagements/${encodeURIComponent(engagementId)}/agent/sessions/${encodeURIComponent(sessionId)}/decisions`,
    )
    return (r?.decisions ?? []) as AgentDecision[]
  },

  agentPlan: async (engagementId: string, sessionId: string): Promise<AgentPlan | null> => {
    const r = await req(
      `/engagements/${encodeURIComponent(engagementId)}/agent/sessions/${encodeURIComponent(sessionId)}/plan`,
    )
    return (r?.plan ?? null) as AgentPlan | null
  },

  decideAgentApproval: async (engagementId: string, actionId: string, approve: boolean, reason: string): Promise<void> => {
    await req(`/engagements/${encodeURIComponent(engagementId)}/agent/approvals/${encodeURIComponent(actionId)}/decide`, {
      method: 'POST',
      body: JSON.stringify({ approve, reason }),
    })
  },
}
