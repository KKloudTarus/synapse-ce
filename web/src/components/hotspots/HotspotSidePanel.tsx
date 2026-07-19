import { useEffect, useState, useRef } from 'react'
import { X, CalendarClock, ShieldAlert, CheckCircle2, ShieldCheck, Shield, AlertTriangle } from 'lucide-react'
import { api, ApiError } from '../../lib/api'
import type { Hotspot, HotspotReviewEvent, HotspotStatus } from '../../lib/types'
import { Button, ErrorState, Pill, Spinner, cn } from '../ui'
import { CanTransitionTo } from '../../lib/types'
import type { CurrentUser } from '../../lib/types'

function StatusIcon({ status, className }: { status: HotspotStatus; className?: string }) {
  switch (status) {
    case 'to_review': return <ShieldAlert className={cn('text-high', className)} />
    case 'acknowledged': return <AlertTriangle className={cn('text-medium', className)} />
    case 'fixed': return <CheckCircle2 className={cn('text-accent', className)} />
    case 'safe': return <ShieldCheck className={cn('text-brand', className)} />
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
  onTransition,
}: {
  projectKey: string
  hotspotId: string
  onClose: () => void
  onTransition?: (hotspot: Hotspot) => void
}) {
  const [hotspot, setHotspot] = useState<Hotspot | null>(null)
  const [history, setHistory] = useState<HotspotReviewEvent[]>([])
  const [me, setMe] = useState<CurrentUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (hotspot && panelRef.current) {
      panelRef.current.focus()
    }
  }, [hotspot])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onClose])
  
  const canReview = me && (me.role === 'admin' || me.role === 'reviewer')

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    Promise.all([
      api.getProjectHotspot(projectKey, hotspotId),
      api.getProjectHotspotHistory(projectKey, hotspotId),
      api.me()
    ])
      .then(([hotspotRes, historyRes, meRes]) => {
        if (!active) return
        setHotspot(hotspotRes)
        setHistory(historyRes)
        setMe(meRes)
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

  const [transitionStatus, setTransitionStatus] = useState<HotspotStatus>('to_review')
  const [rationale, setRationale] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  useEffect(() => {
    if (hotspot) {
      setTransitionStatus(hotspot.status)
      setRationale('')
      setSubmitError(null)
    }
  }, [hotspot?.id])

  const handleTransition = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!hotspot) return
    if (transitionStatus === hotspot.status) {
      setSubmitError('Status must be different from current status.')
      return
    }
    if (rationale.trim().length < 3) {
      setSubmitError('Rationale must be at least 3 characters.')
      return
    }

    setSubmitting(true)
    setSubmitError(null)
    try {
      const res = await api.transitionProjectHotspot(
        projectKey,
        hotspot.id,
        transitionStatus,
        rationale.trim(),
        hotspot.version
      )
      setHotspot(res.hotspot)
      setHistory((prev) => [res.event, ...prev])
      setRationale('')
      onTransition?.(res.hotspot)
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setSubmitError('Another reviewer has updated this hotspot. Please review their changes and try again.')
        try {
          const freshHotspot = await api.getProjectHotspot(projectKey, hotspot.id)
          const freshHistory = await api.getProjectHotspotHistory(projectKey, hotspot.id)
          setHotspot(freshHotspot)
          setHistory(freshHistory)
        } catch {}
      } else {
        setSubmitError(err instanceof ApiError ? err.message : 'Failed to save review')
      }
    } finally {
      setSubmitting(false)
    }
  }

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
    <div 
      className="flex h-full flex-col"
      role="dialog"
      aria-modal="true"
      aria-labelledby="hotspot-dialog-title"
      tabIndex={-1}
      ref={panelRef}
    >
      <div className="flex items-start justify-between border-b border-border bg-surface p-4">
        <div className="flex items-center gap-2">
          <StatusIcon status={hotspot.status} className="size-5" />
          <h2 id="hotspot-dialog-title" className="font-semibold">{formatHotspotStatus(hotspot.status)}</h2>
        </div>
        <button
          aria-label="Close dialog"
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

        {hotspot.status !== 'fixed' || history.some(h => h.status === 'fixed') ? (
          <form onSubmit={handleTransition} className="rounded-lg border border-border bg-surface p-4">
            <h4 className="text-sm font-semibold text-foreground">Review Decision</h4>
            
            {!canReview ? (
              <div className="mt-3 text-sm text-mutedfg p-3 bg-elevated rounded-md">
                You do not have permission to review Security Hotspots.
              </div>
            ) : (
            <div className="mt-3 space-y-3">
              <div>
                <label htmlFor="status" className="sr-only">Status</label>
                <select
                  id="status"
                  value={transitionStatus}
                  onChange={(e) => setTransitionStatus(e.target.value as HotspotStatus)}
                  className="w-full rounded-md border border-border bg-card px-3 py-1.5 text-sm text-foreground focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                  disabled={submitting}
                >
                  <option value={hotspot.status} disabled>{formatHotspotStatus(hotspot.status)} (Current)</option>
                  {CanTransitionTo(hotspot.status, 'to_review') && <option value="to_review">To review</option>}
                  {CanTransitionTo(hotspot.status, 'acknowledged') && <option value="acknowledged">Acknowledged</option>}
                  {CanTransitionTo(hotspot.status, 'fixed') && <option value="fixed">Fixed</option>}
                  {CanTransitionTo(hotspot.status, 'safe') && <option value="safe">Safe</option>}
                </select>
              </div>
              <div>
                <label htmlFor="rationale" className="sr-only">Rationale</label>
                <textarea
                  id="rationale"
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                  placeholder="Provide a rationale for this decision..."
                  className="w-full resize-y rounded-md border border-border bg-card px-3 py-2 text-sm text-foreground focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                  rows={3}
                  disabled={submitting}
                  maxLength={4000}
                />
              </div>
              {submitError && (
                <div className="text-xs text-critical">{submitError}</div>
              )}
              <Button
                type="submit"
                disabled={submitting || (transitionStatus === hotspot.status && rationale.trim().length === 0)}
                className="w-full"
                variant="brand"
              >
                {submitting ? <Spinner className="size-4 mr-2" /> : null}
                Save decision
              </Button>
            </div>
            )}
          </form>
        ) : null}

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
