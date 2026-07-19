import { useEffect, useState } from 'react'
import { X, CalendarClock, ShieldAlert, CheckCircle2, ShieldCheck, Shield, AlertTriangle } from 'lucide-react'
import { api, ApiError } from '../../lib/api'
import type { Hotspot, HotspotReviewEvent, HotspotStatus } from '../../lib/types'
import { Button, ErrorState, Pill, Spinner, cn } from '../ui'

function StatusIcon({ status, className }: { status: HotspotStatus; className?: string }) {
  switch (status) {
    case 'to_review': return <ShieldAlert className={cn('text-orange-500', className)} />
    case 'acknowledged': return <AlertTriangle className={cn('text-yellow-500', className)} />
    case 'fixed': return <CheckCircle2 className={cn('text-green-500', className)} />
    case 'safe': return <ShieldCheck className={cn('text-blue-500', className)} />
    default: return <Shield className={className} />
  }
}

export function formatHotspotStatus(status: HotspotStatus) {
  switch (status) {
    case 'to_review': return 'To review'
    case 'acknowledged': return 'Acknowledged'
    case 'fixed': return 'Fixed'
    case 'safe': return 'Safe'
    default: return status
  }
}

export function HotspotSidePanel({
  projectKey,
  hotspotId,
  onClose,
}: {
  projectKey: string
  hotspotId: string
  onClose: () => void
}) {
  const [hotspot, setHotspot] = useState<Hotspot | null>(null)
  const [history, setHistory] = useState<HotspotReviewEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    Promise.all([
      api.getProjectHotspot(projectKey, hotspotId),
      api.getProjectHotspotHistory(projectKey, hotspotId)
    ])
      .then(([hotspotRes, historyRes]) => {
        if (!active) return
        setHotspot(hotspotRes)
        setHistory(historyRes)
      })
      .catch((err) => {
        if (!active) return
        setError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => { active = false }
  }, [projectKey, hotspotId])

  if (loading && !hotspot) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <Spinner className="size-6 text-brand" />
      </div>
    )
  }

  if (error && !hotspot) {
    return (
      <div className="p-6">
        <ErrorState message={error} />
        <Button variant="secondary" onClick={onClose} className="mt-4 w-full">Close</Button>
      </div>
    )
  }

  if (!hotspot) return null

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-start justify-between border-b border-border bg-surface p-4">
        <div className="flex items-center gap-2">
          <StatusIcon status={hotspot.status} className="size-5" />
          <h2 className="font-semibold">{formatHotspotStatus(hotspot.status)}</h2>
        </div>
        <button
          onClick={onClose}
          className="rounded-md p-1 text-mutedfg hover:bg-bg hover:text-foreground focus:outline-none focus:ring-2 focus:ring-brand/60"
        >
          <X className="size-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        <div>
          <h3 className="text-lg font-medium text-foreground">{hotspot.title}</h3>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            <Pill>{hotspot.ruleKey}</Pill>
            <Pill className="capitalize">{hotspot.severity}</Pill>
            {hotspot.cwe && <Pill>{hotspot.cwe}</Pill>}
          </div>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-foreground">Location</h4>
          <p className="mt-1 font-mono text-xs text-mutedfg break-all">{hotspot.location}</p>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-foreground">Description</h4>
          <p className="mt-1 whitespace-pre-wrap text-sm text-mutedfg">
            {hotspot.description || 'No description provided.'}
          </p>
        </div>

        {/* Placeholder for Phase 8 Review Form */}
        <div className="rounded-lg border border-border bg-surface p-4">
          <p className="text-center text-sm text-mutedfg">
            Review form will be implemented in Phase 8.
          </p>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-foreground">Review History</h4>
          {history.length === 0 ? (
            <p className="mt-2 text-xs text-mutedfg">No review history available.</p>
          ) : (
            <div className="mt-3 space-y-4">
              {history.map((event, i) => (
                <div key={i} className="flex gap-3 text-sm">
                  <div className="mt-0.5 flex flex-col items-center">
                    <StatusIcon status={event.status} className="size-4" />
                    {i < history.length - 1 && <div className="mt-2 w-[1px] flex-1 bg-border" />}
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="font-medium text-foreground">{event.actor}</span>
                      <span className="text-mutedfg">changed status to</span>
                      <span className="font-medium text-foreground">{formatHotspotStatus(event.status)}</span>
                    </div>
                    <div className="mt-1 flex items-center gap-1.5 text-xs text-subtlefg">
                      <CalendarClock className="size-3" />
                      {new Date(event.at).toLocaleString()}
                    </div>
                    {event.rationale && (
                      <div className="mt-2 rounded bg-surface p-2 text-xs text-mutedfg">
                        {event.rationale}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
