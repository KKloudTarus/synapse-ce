import {
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  FileCheck02,
  HelpCircle,
  Loading01,
  Target04,
  XClose,
} from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { Tooltip, TooltipTrigger } from '@/components/base/tooltip/tooltip'
import { cn } from '../../../components/ui'
import type { ScanDebugEvent } from '../../../lib/types'

export function fmtDebugDuration(ms: number) {
  if (ms < 1000) return `${Math.max(0, ms)}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

export function formatDebugCounts(counts: Record<string, number>) {
  const entries = Object.entries(counts ?? {})
  if (entries.length === 0) return ''
  return entries.map(([key, value]) => `${key.replaceAll('_', ' ')}: ${value}`).join(' · ')
}

const PROCESSING_KEYS = new Set([
  'attempted',
  'candidates',
  'critiqued',
  'gate_exempt',
  'max_findings',
  'input_count',
  'total',
  'processed',
])

const DECISION_KEYS = new Set([
  'review_required',
  'skipped_budget',
  'suspected_fp',
  'would_exempt',
  'exempt',
  'allowed',
  'denied',
  'passed',
  'failed',
  'verified',
])

function StepInspectorCard({ event }: { event: ScanDebugEvent }) {
  const [showDetails, setShowDetails] = useState(false)

  const counts = event.counts ?? {}
  const countEntries = Object.entries(counts)

  // Split into Processing and Decision groups if applicable
  let processingEntries = countEntries.filter(([k]) => PROCESSING_KEYS.has(k.toLowerCase()))
  let decisionEntries = countEntries.filter(([k]) => DECISION_KEYS.has(k.toLowerCase()))

  // Fallback if keys don't match predefined sets
  if (processingEntries.length === 0 && decisionEntries.length === 0 && countEntries.length > 0) {
    const mid = Math.ceil(countEntries.length / 2)
    processingEntries = countEntries.slice(0, mid)
    decisionEntries = countEntries.slice(mid)
  }

  const hasMetrics = countEntries.length > 0

  return (
    <div className="rounded-2xl border border-secondary bg-primary p-4 sm:p-5 shadow-xs space-y-4 transition-all">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          {/* Target/Status Icon Box */}
          <div
            className={cn(
              'flex size-10 shrink-0 items-center justify-center rounded-xl border',
              event.status === 'failed'
                ? 'border-error bg-error-primary text-error-primary'
                : event.status === 'running'
                  ? 'border-brand bg-primary text-brand-secondary'
                  : 'border-utility-green-300 bg-success-primary text-success-primary',
            )}
          >
            {event.status === 'failed' ? (
              <AlertTriangle className="size-5" />
            ) : event.status === 'running' ? (
              <Loading01 className="size-5 animate-spin" />
            ) : (
              <Target04 className="size-5" />
            )}
          </div>

          {/* Title & Metadata */}
          <div className="flex flex-wrap items-center gap-2.5">
            <h3 className="font-mono text-base font-bold text-primary sm:text-lg">
              {event.step || event.stage}
            </h3>

            {/* Status Pill */}
            <span
              className={cn(
                'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold capitalize',
                event.status === 'failed'
                  ? 'border-error bg-error-primary text-error-primary'
                  : event.status === 'running'
                    ? 'border-brand bg-primary text-brand-secondary'
                    : 'border-utility-green-300 bg-success-primary text-success-primary',
              )}
            >
              {event.status === 'succeeded' && <CheckCircle className="size-3.5" />}
              {event.status === 'failed' && <AlertTriangle className="size-3.5" />}
              {event.status === 'running' && <Loading01 className="size-3.5 animate-spin" />}
              <span>{event.status}</span>
            </span>

            {/* Duration */}
            <span className="flex items-center gap-1.5 font-mono text-xs font-semibold text-tertiary">
              <Clock className="size-3.5 text-quaternary" />
              <span>{event.status === 'running' ? 'in progress' : fmtDebugDuration(event.durationMs)}</span>
            </span>
          </div>
        </div>

        {/* View Details Button */}
        <button
          type="button"
          onClick={() => setShowDetails(!showDetails)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-primary px-3 py-1.5 text-xs font-semibold text-secondary hover:bg-secondary hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
        >
          <span>View details</span>
          {showDetails ? <ChevronUp className="size-3.5 text-tertiary" /> : <ChevronDown className="size-3.5 text-tertiary" />}
        </button>
      </div>

      {/* Error Message if any */}
      {event.error && (
        <div className="rounded-lg border border-error bg-error-primary p-3 text-xs font-semibold text-error-primary">
          {event.error}
        </div>
      )}

      {/* Structured Metrics Groups */}
      {hasMetrics && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {/* Card 1: Processing */}
          {processingEntries.length > 0 && (
            <div className="rounded-xl border border-secondary bg-secondary p-3.5 space-y-2.5">
              <div className="flex items-center gap-1.5 text-xs font-bold text-brand-secondary">
                <Target04 className="size-4" />
                <span>Processing</span>
              </div>
              <div className="flex items-center divide-x divide-secondary overflow-x-auto">
                {processingEntries.map(([k, v]) => (
                  <div key={k} className="flex-1 min-w-[4.5rem] px-2 first:pl-0 last:pr-0 text-center space-y-0.5">
                    <div className="text-[11px] font-semibold text-tertiary capitalize truncate" title={k.replaceAll('_', ' ')}>
                      {k.replaceAll('_', ' ')}
                    </div>
                    <div
                      className={cn(
                        'font-mono text-lg sm:text-xl font-extrabold tabular-nums',
                        v > 0 ? 'text-brand-solid' : 'text-tertiary',
                      )}
                    >
                      {v}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Card 2: Decision */}
          {decisionEntries.length > 0 && (
            <div className="rounded-xl border border-secondary bg-secondary p-3.5 space-y-2.5">
              <div className="flex items-center gap-1.5 text-xs font-bold text-utility-blue-700">
                <FileCheck02 className="size-4" />
                <span>Decision</span>
              </div>
              <div className="flex items-center divide-x divide-secondary overflow-x-auto">
                {decisionEntries.map(([k, v]) => (
                  <div key={k} className="flex-1 min-w-[4.5rem] px-2 first:pl-0 last:pr-0 text-center space-y-0.5">
                    <div className="text-[11px] font-semibold text-tertiary capitalize truncate" title={k.replaceAll('_', ' ')}>
                      {k.replaceAll('_', ' ')}
                    </div>
                    <div
                      className={cn(
                        'font-mono text-lg sm:text-xl font-extrabold tabular-nums',
                        v > 0 ? 'text-utility-blue-700' : 'text-tertiary',
                      )}
                    >
                      {v}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Raw Details Expansion */}
      {showDetails && (
        <div className="rounded-xl border border-secondary bg-primary p-3.5 font-mono text-xs text-tertiary space-y-2">
          <div className="text-[11px] font-bold text-secondary uppercase tracking-wider">Raw Step Event Payload</div>
          <pre className="overflow-x-auto rounded-lg border border-secondary bg-secondary p-3 text-[11px] text-primary">
            {JSON.stringify(event, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export function ScanDebugTimeline({ events, running }: { events: ScanDebugEvent[]; running: boolean }) {
  if (!events.length && !running) return null
  const [selectedIdx, setSelectedIdx] = useState<number>(Math.max(0, events.length - 1))

  // Update selected index when new events arrive
  useEffect(() => {
    if (events.length > 0) {
      setSelectedIdx(events.length - 1)
    }
  }, [events.length])

  const selectedEvent = events[selectedIdx] ?? events[events.length - 1]

  return (
    <details className="group mt-3 text-xs" open={running || events.length > 0}>
      <summary className="inline-flex cursor-pointer select-none items-center gap-1.5 font-semibold text-secondary transition-colors hover:text-primary">
        <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
        <span>Pipeline Journey Track</span>
        <span onClick={(e) => e.stopPropagation()} className="inline-flex items-center">
          <Tooltip
            title="Pipeline Journey"
            description="Language detection → SBOM (Syft) → Vulnerability/License scan → Finding correlation."
            placement="top"
            delay={0}
            arrow
          >
            <TooltipTrigger className="inline-flex cursor-help items-center text-tertiary hover:text-primary">
              <HelpCircle className="size-3.5" />
            </TooltipTrigger>
          </Tooltip>
        </span>
        {events.length > 0 && (
          <span className="rounded-full bg-secondary px-1.5 py-0.2 font-mono text-[10px] font-bold tabular-nums text-tertiary">
            {events.length} steps
          </span>
        )}
      </summary>

      <div className="mt-2.5 rounded-xl border border-secondary bg-primary p-3.5 shadow-2xs">
        {events.length === 0 ? (
          <div className="flex items-center gap-2 py-2 text-tertiary">
            <Loading01 className="size-4 animate-spin text-brand-secondary" />
            <span>Waiting for scan steps…</span>
          </div>
        ) : (
          <div className="space-y-3">
            {/* Horizontal Timeline Rail (Scrollable) with Directed Connectors */}
            <div className="relative overflow-x-auto pb-2 pt-1">
              <div className="flex items-center gap-1.5 min-w-max px-1">
                {events.map((event, idx) => {
                  const failed = event.status === 'failed'
                  const isRunningStep = event.status === 'running'
                  const isSelected = selectedIdx === idx
                  const Icon = failed ? XClose : isRunningStep ? Loading01 : CheckCircle

                  return (
                    <div key={`${event.stage}-${event.step}-${idx}`} className="flex items-center">
                      {/* Step Milestone Node */}
                      <button
                        type="button"
                        onClick={() => setSelectedIdx(idx)}
                        className={cn(
                          'group relative flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-left transition-all',
                          isSelected
                            ? 'border-brand-solid bg-brand-primary shadow-xs ring-1 ring-brand-solid'
                            : 'border-secondary bg-secondary hover:border-brand-solid hover:bg-primary',
                        )}
                        title={`Click to inspect step: ${event.step || event.stage}`}
                      >
                        <span
                          className={cn(
                            'flex size-5 shrink-0 items-center justify-center rounded-full border',
                            failed
                              ? 'border-error bg-error-primary text-fg-error-primary'
                              : isRunningStep
                                ? 'border-brand bg-primary text-brand-secondary'
                                : 'border-utility-green-400 bg-primary text-fg-success-primary',
                          )}
                        >
                          <Icon className={cn('size-3.5', isRunningStep && 'animate-spin')} />
                        </span>

                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span
                              className={cn(
                                'truncate font-mono text-xs font-semibold',
                                isSelected ? 'text-brand-secondary' : 'text-primary',
                              )}
                            >
                              {event.step || event.stage}
                            </span>
                            <span className="font-mono text-[10px] tabular-nums text-tertiary">
                              {isRunningStep ? 'running' : fmtDebugDuration(event.durationMs)}
                            </span>
                          </div>
                        </div>
                      </button>

                      {/* Directed Arrow Connector to next step */}
                      {idx < events.length - 1 && (
                        <div className="mx-1.5 flex items-center shrink-0">
                          <div
                            className={cn(
                              'h-0.5 w-2.5',
                              event.status === 'succeeded' ? 'bg-brand-solid' : 'bg-secondary',
                            )}
                          />
                          <ArrowRight
                            className={cn(
                              'size-3.5 -ml-1',
                              event.status === 'succeeded'
                                ? 'text-brand-secondary font-bold'
                                : 'text-quaternary',
                            )}
                          />
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Selected Step Inspector Card matching customer mockup */}
            {selectedEvent && <StepInspectorCard event={selectedEvent} />}
          </div>
        )}
      </div>
    </details>
  )
}
