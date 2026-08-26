import type { ReconRun, ReconTool } from '../types'
import { ApiError, getToken, getOnUnauthorized, req } from './client'
import { mapEngagement } from './engagements'
import type { Engagement } from '../types'

// ReconLogEvent is one parsed SSE frame from a run's live log stream.
export interface ReconLogEvent {
  id: number
  line?: string
  done?: boolean
}

/**
 * Stream a recon run's logs over SSE. We use fetch (not EventSource) because the
 * browser EventSource API cannot attach the bearer token header. Resolves when the
 * stream ends (done event or the body closes); reconnect by calling again with the
 * last seen event id. Abort via opts.signal.
 */
export async function streamReconLogs(
  engagementId: string,
  runId: string,
  opts: { lastEventId?: number; signal?: AbortSignal; onEvent: (e: ReconLogEvent) => void },
): Promise<void> {
  const id = encodeURIComponent(engagementId)
  const rid = encodeURIComponent(runId)
  const qs = opts.lastEventId ? `?lastEventId=${opts.lastEventId}` : ''
  const token = getToken()
  const onUnauthorized = getOnUnauthorized()
  const res = await fetch(`/api/v1/engagements/${id}/recon/runs/${rid}/logs${qs}`, {
    headers: token ? { authorization: `Bearer ${token}`, accept: 'text/event-stream' } : { accept: 'text/event-stream' },
    signal: opts.signal,
  })
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok || !res.body) throw new ApiError(res.status, `log stream HTTP ${res.status}`)

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
        opts.onEvent({ id: evId, done: true })
        return
      }
      try {
        const parsed = JSON.parse(data) as { line?: string }
        opts.onEvent({ id: evId, line: parsed.line })
      } catch {
        /* keep-alive / non-JSON frame */
      }
    }
  }
}

export const reconApi = {
  reconTools: async (): Promise<ReconTool[]> => (await req('/recon/tools')) ?? [],

  startReconRun: async (engagementId: string, tool: string, target: string): Promise<ReconRun> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/recon/runs`, {
      method: 'POST',
      body: JSON.stringify({ tool, target }),
    }),

  reconRuns: async (engagementId: string): Promise<ReconRun[]> =>
    (await req(`/engagements/${encodeURIComponent(engagementId)}/recon/runs`)) ?? [],

  reconRun: async (engagementId: string, runId: string): Promise<ReconRun> =>
    req(`/engagements/${encodeURIComponent(engagementId)}/recon/runs/${encodeURIComponent(runId)}`),

  setLiveRecon: async (engagementId: string, enabled: boolean): Promise<Engagement> =>
    mapEngagement(
      await req(`/engagements/${encodeURIComponent(engagementId)}/live-recon`, {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }),
    ),
}
