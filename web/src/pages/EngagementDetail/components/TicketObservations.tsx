import { useEffect, useState } from 'react'
import { Button, ErrorState, Spinner } from '../../../components/ui'
import { api } from '../../../lib/api'
import type { TicketInboundView } from '../../../lib/api/ticketing'

export function TicketObservations({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const [view, setView] = useState<TicketInboundView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    let live = true
    setView(null); setError(null)
    api.ticketObservations(engagementId, findingId).then((value) => { if (live) setView(value) }, (cause) => { if (live) setError(cause instanceof Error ? cause.message : 'Could not load Jira observations.') })
    return () => { live = false }
  }, [engagementId, findingId, refresh])
  return <div className="space-y-2 border-t border-secondary pt-3" aria-label="Jira observations">
    <div className="flex items-center justify-between"><p className="text-xs font-medium text-secondary">Jira observations</p><Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => setRefresh((value) => value + 1)}>Refresh observations</Button></div>
    {error ? <ErrorState message={error} /> : !view ? <Spinner label="Loading Jira observations…" /> : <>
      {view.observations.length === 0 && view.proposals.length === 0 && view.comments.length === 0 && <p className="text-xs text-tertiary">No Jira observations yet.</p>}
      {view.observations.map((item, index) => <p key={`${item.remoteId}:${index}`} className="text-xs text-secondary">{item.remoteId} · {item.deletedOrUnreadable ? 'Deleted or no longer readable in Jira' : item.category}</p>)}
      {view.proposals.length > 0 && <div className="space-y-1"><p className="text-xs text-secondary">Retest proposals</p><p className="text-xs text-tertiary">Review the Jira closure and record a retest through the finding workflow.</p>{view.proposals.map((proposal) => <div key={proposal.id}><p className="text-xs text-primary">{proposal.remoteId} · Retest requested · {proposal.state}</p>{proposal.resolutionContext && <p className="text-xs text-tertiary">Resolution context: {proposal.resolutionContext}</p>}</div>)}</div>}
      {view.comments.map((comment) => <div key={comment.id} className="rounded border border-secondary p-2"><p className="text-xs text-tertiary">External · {comment.remoteId}</p><p className="whitespace-pre-wrap break-words text-sm text-primary">{comment.body}</p></div>)}
    </>}
  </div>
}
