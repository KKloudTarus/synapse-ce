import {
  AlertTriangle,
  ArrowRight,
  Check,
  Clock as CalendarClock,
  Copy01,
  File02,
  LinkExternal02,
  ShieldTick,
  XClose as X,
} from '@untitledui/icons'
import { copyText } from '../../lib/clipboard'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../../lib/api'
import { CanTransitionTo, type CurrentUser, type Hotspot, type HotspotReviewEvent, type HotspotStatus } from '../../lib/types'
import { Button, ErrorState, Spinner, cn } from '../ui'
import { StatusIcon, formatHotspotStatus, parseDescription, severityBadgeStyle, statusBadgeStyle } from './hotspotHelpers'

// Re-export for existing consumers that import it from this module.
export { formatHotspotStatus } from './hotspotHelpers'

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
  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState<'risk' | 'decision'>('risk')

  const panelRef = useRef<HTMLDivElement>(null)

  function copyLocation(text: string) {
    if (!text) return
    copyText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

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
      api.me(),
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
        hotspot.version,
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

  const parsedBullets = parseDescription(hotspot.description)

  return (
    <div
      className="flex h-full flex-col overflow-hidden"
      role="region"
      aria-label="Hotspot inspector"
      tabIndex={-1}
      ref={panelRef}
    >
      {/* Top Header Card */}
      <div className="border-b border-secondary bg-primary p-5 shadow-2xs">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 space-y-2">
            <h2 className="text-lg font-bold text-primary leading-snug break-words">
              {hotspot.title}
            </h2>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 font-semibold border', statusBadgeStyle(hotspot.status))}>
                <StatusIcon status={hotspot.status} className="size-3.5" />
                {formatHotspotStatus(hotspot.status)}
              </span>
              <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 font-mono font-bold uppercase border', severityBadgeStyle(hotspot.severity))}>
                {hotspot.severity}
              </span>
              <Link
                to={`/rules/${encodeURIComponent(hotspot.ruleKey)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 rounded-md border border-secondary bg-secondary px-2 py-0.5 font-mono text-brand-secondary hover:underline"
                title="View Rule Specification"
              >
                <span>{hotspot.ruleKey}</span>
                <LinkExternal02 className="size-3" aria-hidden="true" />
              </Link>
              {hotspot.cwe && (
                <span className="rounded-md border border-secondary bg-secondary px-2 py-0.5 font-mono text-secondary">
                  {hotspot.cwe}
                </span>
              )}
            </div>
          </div>
          <button
            type="button"
            aria-label="Close inspector"
            onClick={onClose}
            className="rounded-lg p-1.5 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus:outline-none focus:ring-2 focus:ring-brand/60 shrink-0"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Location chip row */}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary/30 px-3 py-2 text-xs">
          <div className="flex items-center gap-1.5 min-w-0 font-mono text-primary truncate">
            <File02 className="size-3.5 text-tertiary shrink-0" aria-hidden="true" />
            <span className="truncate">{hotspot.location}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => copyLocation(hotspot.location)}
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium text-tertiary hover:bg-secondary hover:text-primary transition-colors"
              title={copied ? 'Copied location!' : 'Copy file path'}
            >
              {copied ? <Check className="size-3 text-success-primary" /> : <Copy01 className="size-3" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <Link
              to={`/code-quality/projects/${encodeURIComponent(projectKey)}/code`}
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold text-brand-secondary hover:underline"
            >
              <span>View Code</span>
              <ArrowRight className="size-3" aria-hidden="true" />
            </Link>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="mt-4 flex items-center gap-2 border-t border-secondary pt-3" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'risk'}
            onClick={() => setActiveTab('risk')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold transition-all',
              activeTab === 'risk'
                ? 'bg-brand-primary/15 text-brand-secondary border border-brand/30 shadow-2xs'
                : 'text-tertiary hover:bg-secondary hover:text-primary border border-transparent',
            )}
          >
            <AlertTriangle className="size-3.5" aria-hidden="true" />
            <span>Risk Analysis</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'decision'}
            onClick={() => setActiveTab('decision')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold transition-all',
              activeTab === 'decision'
                ? 'bg-brand-primary/15 text-brand-secondary border border-brand/30 shadow-2xs'
                : 'text-tertiary hover:bg-secondary hover:text-primary border border-transparent',
            )}
          >
            <ShieldTick className="size-3.5" aria-hidden="true" />
            <span>Review & Audit</span>
          </button>
        </div>
      </div>

      {/* Tab Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {activeTab === 'risk' && (
          <div className="space-y-5 animate-fade-in">
            {/* Finding Evidence */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-tertiary mb-2.5">
                Finding Evidence
              </h3>
              {parsedBullets.length > 0 ? (
                <div className="space-y-2.5">
                  {parsedBullets.map((item, idx) => (
                    <div key={idx} className="rounded-xl border border-secondary bg-primary p-3.5 shadow-2xs">
                      {item.key && (
                        <div className="mb-1 font-bold text-xs text-primary capitalize tracking-wide">
                          {item.key}
                        </div>
                      )}
                      <div className="text-secondary leading-relaxed font-mono whitespace-pre-wrap break-words text-[11.5px]">
                        {item.text}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-xl border border-secondary bg-secondary/20 p-4 text-xs text-tertiary">
                  No automated evidence recorded for this finding.
                </div>
              )}
            </div>

            {/* Context & Policy */}
            <div className="rounded-xl border border-warning-primary/40 bg-warning-primary/10 p-4 shadow-2xs">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="size-4 text-warning-primary shrink-0 mt-0.5" aria-hidden="true" />
                <div className="text-xs space-y-1">
                  <div className="font-bold text-warning-primary">Triage Policy</div>
                  <div className="text-secondary leading-relaxed">
                    Hotspots indicate security-sensitive patterns. Validate sanitization, reachability, and source-to-sink boundaries before classifying as Safe.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'decision' && (
          <div className="space-y-6 animate-fade-in">
            {/* Review Decision Form */}
            {hotspot.status !== 'fixed' || history.some((h) => h.status === 'fixed') ? (
              <form onSubmit={handleTransition} className="rounded-xl border border-secondary bg-primary p-5 shadow-xs space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-wider text-primary">
                  Review Classification
                </h3>

                {!canReview ? (
                  <div className="rounded-md bg-secondary p-3 text-xs text-tertiary">
                    You do not have permission to review Security Hotspots in this project.
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div>
                      <label className="text-xs font-medium text-secondary mb-2 block">
                        Target Status
                      </label>
                      <div className="grid grid-cols-2 gap-2.5">
                        {(['safe', 'acknowledged', 'fixed', 'to_review'] as HotspotStatus[]).map((st) => {
                          const allowed = CanTransitionTo(hotspot.status, st) || st === hotspot.status
                          const isCurrent = hotspot.status === st
                          const isSelected = transitionStatus === st
                          return (
                            <button
                              key={st}
                              type="button"
                              disabled={!allowed || submitting}
                              onClick={() => setTransitionStatus(st)}
                              className={cn(
                                'flex items-center justify-between rounded-lg border p-2.5 text-xs font-semibold transition-all',
                                isSelected
                                  ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
                                  : 'border-secondary bg-secondary/40 text-secondary hover:bg-secondary hover:text-primary',
                                !allowed && 'opacity-40 pointer-events-none',
                              )}
                            >
                              <span className="flex items-center gap-1.5">
                                <StatusIcon status={st} className="size-3.5 shrink-0" />
                                {formatHotspotStatus(st)}
                              </span>
                              {isCurrent && (
                                <span className="text-[10px] font-normal text-tertiary">(Current)</span>
                              )}
                            </button>
                          )
                        })}
                      </div>
                    </div>

                    <div>
                      <label htmlFor="rationale" className="text-xs font-medium text-secondary mb-1.5 block">
                        Rationale <span className="text-error-primary">*</span>
                      </label>
                      <textarea
                        id="rationale"
                        value={rationale}
                        onChange={(e) => setRationale(e.target.value)}
                        placeholder="Enter triage notes or justification for this status change..."
                        className="w-full resize-y rounded-lg border border-secondary bg-primary px-3 py-2 text-xs text-primary shadow-2xs focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
                        rows={3}
                        disabled={submitting}
                        maxLength={4000}
                      />
                    </div>

                    {submitError && (
                      <div className="text-xs font-medium text-error-primary">{submitError}</div>
                    )}

                    <Button
                      type="submit"
                      disabled={submitting || (transitionStatus === hotspot.status && rationale.trim().length === 0)}
                      className="w-full !bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs font-semibold"
                      variant="primary"
                    >
                      {submitting ? <Spinner className="mr-2 size-4" /> : null}
                      Save Decision
                    </Button>
                  </div>
                )}
              </form>
            ) : null}

            {/* Audit Trail Timeline */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-tertiary mb-3">
                Audit Trail
              </h3>
              {history.length === 0 ? (
                <p className="text-xs text-tertiary">No review history recorded yet.</p>
              ) : (
                <div className="space-y-4">
                  {history.map((event, i) => (
                    <div key={i} className="flex gap-3 text-xs">
                      <div className="mt-0.5 flex flex-col items-center">
                        <StatusIcon status={event.status} className="size-4 shrink-0" />
                        {i < history.length - 1 && <div className="mt-2 w-[1px] flex-1 bg-secondary" />}
                      </div>
                      <div className="flex-1 pb-4">
                        <div className="flex flex-wrap items-baseline gap-1.5">
                          <span className="font-bold text-primary">{event.actor}</span>
                          <span className="text-tertiary">changed status to</span>
                          <span className={cn('inline-flex items-center rounded px-1.5 py-0.2 font-semibold border', statusBadgeStyle(event.status))}>
                            {formatHotspotStatus(event.status)}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center gap-1 text-[11px] text-tertiary">
                          <CalendarClock className="size-3" />
                          {new Date(event.at).toLocaleString()}
                        </div>
                        {event.rationale && (
                          <div className="mt-2 rounded-lg border border-secondary bg-secondary/30 p-2.5 text-xs text-secondary shadow-2xs">
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
        )}
      </div>
    </div>
  )
}
