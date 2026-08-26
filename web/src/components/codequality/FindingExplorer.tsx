import {
  ChevronDown,
  SearchLg as Search,
  ShieldTick,
  XClose,
} from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import {
  findingMatchesRatedDimension,
  ratedFindingDimensionLabel,
  ratedFindingDimensionValues,
  type RatedFindingDimension,
} from '../../lib/ratedFindingDimensions'
import type { AITriage, Finding } from '../../lib/types'
import { AITriageBadges } from '../synapse/AITriageBadges'
import { Card, EmptyState, Pill, Select, SevBadge, cn } from '../ui'

const pageSize = 50
const findingKey = (finding: Finding) => JSON.stringify([finding.id ?? '', finding.dedupKey ?? ''])
type FindingKindFilter = 'all' | `dimension:${RatedFindingDimension}` | `kind:${string}`

export function FindingExplorer({
  findings,
  headingId,
  initialDimension = null,
  dimensionNavigationKey,
  aiTriage = [],
}: {
  findings: Finding[]
  headingId?: string
  initialDimension?: RatedFindingDimension | null
  dimensionNavigationKey?: string
  aiTriage?: AITriage[]
}) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [kindFilter, setKindFilter] = useState<FindingKindFilter>(() => dimensionFilter(initialDimension))
  const [selected, setSelected] = useState<Finding | null>(null)
  const [shown, setShown] = useState(pageSize)
  const kinds = useMemo(() => [...new Set(findings.map((finding) => finding.kind))].sort(), [findings])

  const triageByFinding = useMemo(() => {
    const map = new Map<string, AITriage>()
    aiTriage.forEach((item) => {
      if (item.findingId) map.set(item.findingId, item)
      if (item.dedupKey) map.set(item.dedupKey, item)
    })
    return map
  }, [aiTriage])

  const triageFor = (finding: Finding) => triageByFinding.get(finding.id) ?? triageByFinding.get(finding.dedupKey)

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return findings.filter(
      (finding) =>
        (!needle || `${finding.title} ${finding.description} ${finding.cwe}`.toLowerCase().includes(needle)) &&
        (severity === 'all' || finding.severity === severity) &&
        matchesKindFilter(finding, kindFilter),
    )
  }, [findings, kindFilter, query, severity])

  const rendered = visible.slice(0, shown)

  useEffect(() => {
    setKindFilter(dimensionFilter(initialDimension))
    setSelected(null)
  }, [dimensionNavigationKey, initialDimension])

  useEffect(() => setShown(pageSize), [visible])

  useEffect(() => {
    setSelected((current) => (current ? visible.find((finding) => findingKey(finding) === findingKey(current)) ?? null : null))
  }, [visible])

  return (
    <Card
      title="Analysis findings"
      titleId={headingId}
      titleTabIndex={headingId ? -1 : undefined}
      titleClassName={headingId ? 'scroll-mt-6 rounded-sm focus:outline-none focus:ring-2 focus:ring-brand/60' : undefined}
      actions={<Pill className="tabular-nums font-semibold">{findings.length.toLocaleString()} findings</Pill>}
      bodyClass="p-0"
    >
      {findings.length === 0 ? (
        <div className="p-6">
          <EmptyState icon={Search} title="No analysis findings" hint="This analysis did not produce publishable findings." />
        </div>
      ) : (
        <>
          {/* Filter Bar */}
          <div className="grid gap-3 border-b border-secondary bg-secondary/20 p-3 md:grid-cols-[1fr_11rem_13rem]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-tertiary" aria-hidden="true" />
              <input
                type="text"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search title, description, or CWE..."
                aria-label="Search findings"
                className="w-full rounded-lg border border-secondary bg-primary py-1.5 pl-8 pr-7 text-xs text-primary shadow-2xs placeholder:text-tertiary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
              />
              {query && (
                <button
                  type="button"
                  onClick={() => setQuery('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary hover:bg-secondary hover:text-primary"
                  aria-label="Clear search"
                >
                  <XClose className="size-3" />
                </button>
              )}
            </div>

            <Select
              value={severity}
              onValueChange={setSeverity}
              ariaLabel="Filter findings by severity"
              size="sm"
              options={[
                { value: 'all', label: 'All severities' },
                ...['critical', 'high', 'medium', 'low', 'info', 'unknown'].map((value) => ({
                  value,
                  label: value,
                })),
              ]}
            />

            <Select
              value={kindFilter}
              onValueChange={(value) => setKindFilter(value as FindingKindFilter)}
              ariaLabel="Filter findings by kind"
              size="sm"
              options={[
                { value: 'all', label: 'All kinds' },
                ...ratedFindingDimensionValues.map((dimension) => ({
                  value: `dimension:${dimension}`,
                  label: ratedFindingDimensionLabel(dimension),
                })),
                ...kinds.map((value) => ({
                  value: `kind:${value}`,
                  label: value || 'Legacy security kind',
                })),
              ]}
            />
          </div>

          {/* Master Detail Split */}
          <div className="grid min-h-[32rem] md:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
            {/* Findings List (Left) */}
            <div className="max-h-[38rem] divide-y divide-secondary/40 overflow-y-auto bg-primary">
              {visible.length === 0 ? (
                <div className="p-8 text-center text-xs text-tertiary">
                  No findings match the selected filters.
                </div>
              ) : (
                <>
                  {rendered.map((finding) => {
                    const triage = triageFor(finding)
                    const isSelected = selected !== null && findingKey(selected) === findingKey(finding)

                    return (
                      <button
                        key={findingKey(finding)}
                        type="button"
                        onClick={() => setSelected(finding)}
                        aria-pressed={isSelected}
                        className={cn(
                          'flex w-full items-start gap-3 p-3.5 text-left transition-all border-l-3',
                          isSelected
                            ? 'bg-brand-primary/10 border-l-brand-solid shadow-2xs'
                            : 'border-l-transparent hover:bg-secondary/40',
                        )}
                      >
                        <div className="shrink-0 mt-0.5">
                          <SevBadge sev={finding.severity} />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className={cn('text-xs font-semibold leading-snug line-clamp-2', isSelected ? 'text-brand-secondary' : 'text-primary')}>
                            {finding.title}
                          </div>
                          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-tertiary">
                            <span className="capitalize font-medium">{finding.kind}</span>
                            {finding.cwe && (
                              <span className="rounded bg-secondary px-1 py-0.2 font-mono text-[10px] text-secondary">
                                {finding.cwe}
                              </span>
                            )}
                            <span>·</span>
                            <span className="capitalize font-medium">{finding.status}</span>
                          </div>
                          {triage && (
                            <div className="mt-2">
                              <AITriageBadges triage={triage} />
                            </div>
                          )}
                        </div>
                      </button>
                    )
                  })}
                  {shown < visible.length && (
                    <div className="p-3 bg-secondary/15 border-t border-secondary">
                      <button
                        type="button"
                        onClick={() => setShown((count) => Math.min(count + pageSize, visible.length))}
                        aria-label="Load more findings"
                        className="w-full rounded-lg border border-secondary bg-primary py-2 text-xs font-semibold text-primary hover:bg-secondary transition-colors shadow-2xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                      >
                        Load more findings ({visible.length - shown} remaining)
                      </button>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* Finding Detail Inspector (Right) */}
            <aside className="border-t border-secondary bg-secondary/15 p-5 md:border-l md:border-t-0 max-h-[38rem] overflow-y-auto" aria-label="Finding details">
              {selected ? (
                <div className="space-y-4">
                  {/* Top Badges */}
                  <div className="flex flex-wrap items-center gap-2">
                    <SevBadge sev={selected.severity} />
                    <Pill>{selected.kind}</Pill>
                    {selected.cwe && <Pill className="font-mono">{selected.cwe}</Pill>}
                  </div>

                  {/* Title */}
                  <h3 className="text-sm font-bold text-primary leading-snug">{selected.title}</h3>

                  {/* Quick Meta Grid (Moved up so user immediately sees status and priority) */}
                  <dl className="grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded-lg bg-primary border border-secondary p-2.5">
                      <dt className="text-[11px] text-tertiary font-medium">Status</dt>
                      <dd className="mt-0.5 capitalize font-semibold text-primary">{selected.status}</dd>
                    </div>
                    <div className="rounded-lg bg-primary border border-secondary p-2.5">
                      <dt className="text-[11px] text-tertiary font-medium">Priority</dt>
                      <dd className="mt-0.5 font-semibold text-primary">P{selected.priority || '—'}</dd>
                    </div>
                    <div className="rounded-lg bg-primary border border-secondary p-2.5">
                      <dt className="text-[11px] text-tertiary font-medium">Scope</dt>
                      <dd className="mt-0.5 capitalize font-semibold text-primary">{selected.scope || 'Unspecified'}</dd>
                    </div>
                    <div className="rounded-lg bg-primary border border-secondary p-2.5">
                      <dt className="text-[11px] text-tertiary font-medium">Reachability</dt>
                      <dd className="mt-0.5 capitalize font-semibold text-primary">{selected.reachability || 'Unknown'}</dd>
                    </div>
                  </dl>

                  {/* AI Triage Badges */}
                  {triageFor(selected) && (
                    <div>
                      <AITriageBadges triage={triageFor(selected)!} />
                    </div>
                  )}

                  {/* Collapsible / Progressive Finding Description */}
                  <div>
                    <div className="text-xs font-bold uppercase tracking-wider text-tertiary mb-1.5">
                      Finding Description
                    </div>
                    <FindingDescriptionViewer description={selected.description} />
                  </div>

                  {/* AI Triage Deep Details */}
                  {triageFor(selected) && <AITriageDetails triage={triageFor(selected)!} />}
                </div>
              ) : (
                <div className="flex h-full min-h-48 flex-col items-center justify-center text-center p-6">
                  <div className="p-3 rounded-full bg-secondary text-tertiary mb-3 border border-secondary">
                    <ShieldTick className="size-6" />
                  </div>
                  <p className="text-xs font-semibold text-primary">No Finding Selected</p>
                  <p className="mt-1 text-[11px] text-tertiary max-w-[200px]">
                    Select any finding from the list on the left to inspect its triage evidence and status.
                  </p>
                </div>
              )}
            </aside>
          </div>
        </>
      )}
    </Card>
  )
}

function FindingDescriptionViewer({ description }: { description: string }) {
  const [expandedTrace, setExpandedTrace] = useState(false)
  const [showFull, setShowFull] = useState(false)

  if (!description) {
    return <p className="text-tertiary text-xs italic">No additional description was supplied.</p>
  }

  // Check if description has an AppSec envelope / trace
  const envelopeIndex = description.indexOf('AppSec validation envelope:')

  if (envelopeIndex !== -1) {
    const summary = description.slice(0, envelopeIndex).trim()
    const envelope = description.slice(envelopeIndex).trim()

    return (
      <div className="space-y-2">
        {summary && (
          <div className="rounded-lg border border-secondary bg-primary p-3 text-xs leading-relaxed text-secondary font-medium">
            {summary}
          </div>
        )}
        <div className="rounded-lg border border-secondary/80 bg-secondary/30 overflow-hidden">
          <button
            type="button"
            onClick={() => setExpandedTrace(!expandedTrace)}
            className="flex w-full items-center justify-between px-3 py-2 text-xs font-semibold text-secondary hover:bg-secondary/50 hover:text-primary transition-colors text-left"
          >
            <span className="inline-flex items-center gap-1.5 text-brand-secondary font-bold text-[11px]">
              <span>AppSec Validation Envelope</span>
              <span className="text-[10px] text-tertiary font-normal">
                {expandedTrace ? '(click to collapse)' : '(click to inspect trace)'}
              </span>
            </span>
            <ChevronDown className={cn('size-3.5 transition-transform duration-200', expandedTrace && 'rotate-180')} />
          </button>
          {expandedTrace && (
            <div className="p-3 border-t border-secondary/60 bg-primary font-mono text-[11px] leading-relaxed text-secondary whitespace-pre-wrap max-h-60 overflow-y-auto">
              {envelope}
            </div>
          )}
        </div>
      </div>
    )
  }

  // Generic long text handling
  const isLong = description.length > 250 || description.split('\n').length > 4

  return (
    <div className="rounded-lg border border-secondary bg-primary p-3 space-y-2">
      <div
        className={cn(
          'text-xs leading-relaxed text-secondary font-mono whitespace-pre-wrap transition-all',
          isLong && !showFull && 'line-clamp-4',
        )}
      >
        {description}
      </div>
      {isLong && (
        <button
          type="button"
          onClick={() => setShowFull(!showFull)}
          className="inline-flex items-center gap-1 text-[11px] font-semibold text-brand-secondary hover:underline pt-1 border-t border-secondary/50 w-full"
        >
          <span>{showFull ? 'Show less' : 'Show full description'}</span>
          <ChevronDown className={cn('size-3 transition-transform duration-200', showFull && 'rotate-180')} />
        </button>
      )}
    </div>
  )
}

function AITriageDetails({ triage }: { triage: AITriage }) {
  return (
    <dl className="grid grid-cols-1 gap-2 rounded-xl border border-secondary bg-primary p-3 text-xs">
      <div>
        <dt className="text-[11px] text-tertiary font-medium">Proposer</dt>
        <dd className="mt-0.5 font-medium text-primary">
          {triage.proposerModel} · <strong className="capitalize">{triage.verdict}</strong> · {triage.confidence}%
        </dd>
      </div>
      <div>
        <dt className="text-[11px] text-tertiary font-medium">Verifier</dt>
        <dd className="mt-0.5 font-medium text-primary">
          {triage.verifierModel ? `${triage.verifierModel} · ${triage.verifierVerdict || '—'} · ${triage.verifierConfidence}%` : 'Not attached'}
        </dd>
      </div>
      <div>
        <dt className="text-[11px] text-tertiary font-medium">Policy</dt>
        <dd className="mt-0.5 font-medium text-primary">
          {triage.policyVersion || '—'} · {(triage.policyReason || '—').replaceAll('_', ' ')}
        </dd>
      </div>
    </dl>
  )
}

function dimensionFilter(dimension: RatedFindingDimension | null): FindingKindFilter {
  return dimension === null ? 'all' : `dimension:${dimension}`
}

function matchesKindFilter(finding: Finding, filter: FindingKindFilter): boolean {
  if (filter === 'all') return true
  if (filter.startsWith('dimension:')) {
    return findingMatchesRatedDimension(finding, filter.slice('dimension:'.length) as RatedFindingDimension)
  }
  return finding.kind === filter.slice('kind:'.length)
}
