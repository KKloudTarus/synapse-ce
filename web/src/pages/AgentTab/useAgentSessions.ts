import { useCallback, useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type { AgentReadiness, AgentSession, PendingApproval } from '../../lib/types'

export function useAgentSessions(engagementId: string) {
  const [sessions, setSessions] = useState<AgentSession[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [goal, setGoal] = useState('')
  const [starting, setStarting] = useState(false)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [approvals, setApprovals] = useState<PendingApproval[]>([])
  const [readiness, setReadiness] = useState<AgentReadiness | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [ss, ap, rd] = await Promise.all([
        api.agentSessions(engagementId),
        api.agentApprovals(engagementId),
        api.agentReadiness(engagementId),
      ])
      setSessions(ss)
      setApprovals(ap)
      setReadiness(rd)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load agent sessions')
    }
  }, [engagementId])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [refresh])

  const startWithGoal = useCallback(
    async (g: string) => {
      const goalStr = g.trim()
      if (!goalStr) return
      setStarting(true)
      setError(null)
      try {
        const sess = await api.startAgentSession(engagementId, goalStr)
        setGoal('')
        setActiveId(sess.id)
        await refresh()
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to start the agent')
      } finally {
        setStarting(false)
      }
    },
    [engagementId, refresh],
  )

  async function startAgent() {
    await startWithGoal(goal)
  }

  async function decide(actionId: string, approve: boolean) {
    try {
      await api.decideAgentApproval(engagementId, actionId, approve, approve ? 'approved by operator' : 'denied by operator')
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to record the decision')
    }
  }

  return {
    sessions,
    error,
    goal,
    setGoal,
    starting,
    activeId,
    setActiveId,
    approvals,
    readiness,
    refresh,
    startWithGoal,
    startAgent,
    decide,
  }
}
