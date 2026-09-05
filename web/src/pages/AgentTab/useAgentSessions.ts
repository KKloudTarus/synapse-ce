import { useCallback, useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { isFeatureDisabled } from '../../components/synapse/FeatureDisabledState'
import type { AgentReadiness, AgentSession, PendingApproval } from '../../lib/types'

export function useAgentSessions(engagementId: string) {
  const [sessions, setSessions] = useState<AgentSession[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [goal, setGoal] = useState('')
  const [starting, setStarting] = useState(false)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [approvals, setApprovals] = useState<PendingApproval[]>([])
  const [readiness, setReadiness] = useState<AgentReadiness | null>(null)
  const [disabled, setDisabled] = useState(false)

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
      // The orchestrator is optional; its routes are absent (404) when the switch
      // is off. Report that as a disabled feature, not as a broken page.
      if (isFeatureDisabled(e)) {
        setDisabled(true)
        setSessions([])
        setError(null)
        return
      }
      setError(e instanceof Error ? e.message : 'Failed to load agent sessions')
    }
  }, [engagementId])

  useEffect(() => {
    refresh()
    // Stop polling a feature that answered 404 once.
    if (disabled) return
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [refresh, disabled])

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
    disabled,
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
