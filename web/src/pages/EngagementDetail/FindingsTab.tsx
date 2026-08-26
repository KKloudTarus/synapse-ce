import {
  AlertTriangle,
  CheckCircle,
  CheckVerified01,
  ChevronLeft,
  ChevronRight,
  File06,
  Loading01,
  MessageSquare01,
  Plus,
  RefreshCcw01,
  SearchLg,
  Shield01,
  ShieldTick,
  Stars01,
  User01,
  XClose,
} from '@untitledui/icons'
import { Fragment, useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { AITriageBadges } from '../../components/synapse/AITriageBadges'
import {
  Button,
  Card,
  EmptyState,
  Field,
  Input,
  KevBadge,
  Pill,
  Select,
  SevBadge,
  Spinner,
  cn,
} from '../../components/ui'
import { useFetch } from '../../hooks'
import { ApiError, api } from '../../lib/api'
import { findingKindLabel, statusLabel } from '../../lib/format'
import { sevText } from '../../lib/severity'
import type {
  CritiqueClaim,
  EvidenceItem,
  Finding,
  FindingComment,
  Judgment,
  ReachabilityClaim,
  Retest,
  RetestOutcome,
  RiskNarrativeClaim,
  ScanResult,
  Severity,
  Vulnerability,
  Writeup,
} from '../../lib/types'
import {
  ConfidenceBadge,
  DetectedBy,
  KindBadge,
  PriorityBadge,
  ScopeBadge,
  shortPkg,
  vulnKey,
} from './VulnsTab'

function findingAnchor(id: string) {
  return `finding-${id}`
}

const PAGE_SIZE = 12

function TablePagination({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
}: {
  page: number
  totalPages: number
  total: number
  pageSize: number
  onPageChange: (p: number) => void
}) {
  if (totalPages <= 1) return null
  const start = (page - 1) * pageSize
  const end = Math.min(start + pageSize, total)
  return (
    <div className="flex items-center justify-between border-t border-secondary px-4 py-3">
      <span className="text-xs text-tertiary">
        Showing <span className="font-semibold text-primary">{start + 1}</span> to{' '}
        <span className="font-semibold text-primary">{end}</span> of{' '}
        <span className="font-semibold text-primary">{total}</span> findings
      </span>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 1}
          aria-label="Previous page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:text-quaternary"
        >
          <ChevronLeft className="size-4" aria-hidden="true" />
        </button>
        <span className="text-xs tabular-nums text-tertiary">
          Page <span className="font-semibold text-primary">{page}</span> of{' '}
          <span className="font-semibold text-primary">{totalPages}</span>
        </span>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page === totalPages}
          aria-label="Next page"
          className="inline-flex size-8 items-center justify-center rounded-md border border-secondary text-secondary transition-colors hover:bg-secondary hover:text-primary disabled:cursor-not-allowed disabled:text-quaternary"
        >
          <ChevronRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}

export function FindingsTab({
  findings,
  scan,
  engagementId,
  filter,
  setFilter,
  focusedFindingId,
  onUpdated,
  onReload,
}: {
  findings: Finding[] | null
  scan: ScanResult | null
  engagementId: string
  filter: Severity | 'all'
  setFilter: (v: Severity | 'all') => void
  focusedFindingId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [creating, setCreating] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [kindFilter, setKindFilter] = useState<string>('all')
  const [page, setPage] = useState(1)

  useEffect(() => {
    setPage(1)
  }, [filter, kindFilter, searchQuery])

  // Separate actionable third-party findings from first-party historical advisories
  const thirdParty = (findings ?? []).filter((f) => f.class !== 'first_party_historical')
  const historical = (findings ?? []).filter((f) => f.class === 'first_party_historical')
  const available = new Set(thirdParty.map((f) => f.severity))
  const kinds = Array.from(new Set(thirdParty.map((f) => f.kind).filter(Boolean)))

  // Filter rows by severity, kind, and search query
  const rows = useMemo(() => {
    const q = searchQuery.toLowerCase().trim()
    return thirdParty.filter((f) => {
      const matchSeverity = filter === 'all' || f.severity === filter
      const matchKind = kindFilter === 'all' || f.kind === kindFilter
      const matchSearch =
        !q ||
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        (f.cwe && f.cwe.toLowerCase().includes(q)) ||
        (f.assignee && f.assignee.toLowerCase().includes(q))
      return matchSeverity && matchKind && matchSearch
    })
  }, [thirdParty, filter, kindFilter, searchQuery])

  useEffect(() => {
    if (!focusedFindingId || findings === null) return
    const idx = rows.findIndex((f) => f.id === focusedFindingId)
    if (idx >= 0) {
      setPage(Math.floor(idx / PAGE_SIZE) + 1)
    }
    setExpanded((current) => new Set(current).add(focusedFindingId))
    const frame = requestAnimationFrame(() => {
      document.getElementById(findingAnchor(focusedFindingId))?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    })
    return () => cancelAnimationFrame(frame)
  }, [findings, focusedFindingId, rows])

  const vulnByKey = useMemo(() => {
    const m = new Map<string, Vulnerability>()
    for (const v of scan?.vulnerabilities ?? []) m.set(vulnKey(v), v)
    return m
  }, [scan])

  const triageByKey = useMemo(() => {
    const map = new Map<string, NonNullable<ScanResult['aiTriage']>[number]>()
    for (const item of scan?.aiTriage ?? []) {
      if (item.findingId) map.set(item.findingId, item)
      if (item.dedupKey) map.set(item.dedupKey, item)
    }
    return map
  }, [scan])

  if (findings === null) return <Spinner label="Loading findings..." />

  function toggle(id: string) {
    setExpanded((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4">
      {/* Action and Filter Console Bar */}
      <Card bodyClass="p-3" className="shadow-xs">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          {/* Left: Search input + Severity & Kind filters */}
          <div className="flex flex-1 flex-wrap items-center gap-2.5">
            {/* Search Box */}
            <div className="relative min-w-[16rem] flex-1 sm:max-w-xs">
              <SearchLg className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-fg-tertiary pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings, CVE, CWE, package..."
                className="h-9 w-full rounded-lg border border-secondary bg-primary pl-9 pr-8 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-quaternary hover:text-primary"
                  title="Clear search"
                >
                  <XClose className="size-3.5" />
                </button>
              )}
            </div>

            {/* Severity Filter Dropdown */}
            <Select
              value={filter}
              onValueChange={(v) => setFilter(v as Severity | 'all')}
              size="sm"
              ariaLabel="Filter findings by severity"
              className="min-w-[10rem]"
              options={[
                {
                  value: 'all',
                  label: (
                    <span className="flex items-center gap-2">
                      <span className="size-2 rounded-full bg-utility-gray-400" />
                      <span>All Severities</span>
                    </span>
                  ),
                },
                ...['critical', 'high', 'medium', 'low', 'info'].map((s) => ({
                  value: s,
                  label: (
                    <span className="flex items-center gap-2">
                      <span className={cn('size-2 rounded-full', STATUS_DOT[s] ?? 'bg-utility-gray-400')} />
                      <span className="capitalize">{s}</span>
                    </span>
                  ),
                })),
              ]}
            />

            {/* Kind Filter Dropdown */}
            {kinds.length > 1 && (
              <Select
                value={kindFilter}
                onValueChange={setKindFilter}
                size="sm"
                ariaLabel="Filter findings by kind"
                className="min-w-[9rem]"
                options={[
                  { value: 'all', label: 'All Kinds' },
                  ...kinds.map((k) => ({
                    value: k,
                    label: findingKindLabel(k),
                  })),
                ]}
              />
            )}
          </div>

          {/* Right: Historical counter + New finding button */}
          <div className="flex items-center gap-2 self-end lg:self-auto">
            {historical.length > 0 && (
              <span
                className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-secondary px-2.5 py-1.5 text-xs text-tertiary"
                title="Advisories matched against unversioned modules (excluded from remediation)."
              >
                <File06 className="size-3.5 text-fg-tertiary" />
                <span>{historical.length} historical</span>
              </span>
            )}
            <Button
              variant="primary"
              onClick={() => setCreating((c) => !c)}
              className="inline-flex items-center gap-1.5 h-9 px-3.5 text-xs font-semibold"
            >
              <Plus className="size-4" />
              <span>New finding</span>
            </Button>
          </div>
        </div>
      </Card>

      {/* Creation Modal */}
      {creating && (
        <NewFindingModal
          engagementId={engagementId}
          onCreated={() => {
            setCreating(false)
            onReload()
          }}
          onCancel={() => setCreating(false)}
        />
      )}

      {/* Findings Table */}
      {findings.length === 0 ? (
        <EmptyState
          icon={CheckCircle}
          title="No findings yet"
          hint="Run a scan or add a manual finding above to begin remediation tracking."
        />
      ) : (
        <Card bodyClass="p-0" className="overflow-hidden shadow-xs">
          {rows.length === 0 && (
            <div className="p-8 text-center text-sm text-tertiary">
              No actionable findings match the selected filters
              {filter !== 'all' ? ` (severity: ${filter})` : ''}
              {kindFilter !== 'all' ? ` (kind: ${findingKindLabel(kindFilter)})` : ''}
              {searchQuery ? ` for "${searchQuery}"` : ''}.
            </div>
          )}

          {rows.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-secondary bg-secondary text-[11px] font-bold uppercase tracking-wider text-secondary">
                    <th className="w-8 pl-3 py-2.5" />
                    <th className="px-2 py-2.5">Pri</th>
                    <th className="px-2 py-2.5">Severity</th>
                    <th className="px-4 py-2.5">Finding &amp; Details</th>
                    <th className="px-4 py-2.5">Scope</th>
                    <th className="px-4 py-2.5">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-secondary">
                  {rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map((f) => {
                    const v = vulnByKey.get(f.dedupKey)
                    const triage = triageByKey.get(f.id) ?? triageByKey.get(f.dedupKey)
                    const isOpen = expanded.has(f.id)
                    return (
                      <Fragment key={f.id}>
                        <tr
                          id={findingAnchor(f.id)}
                          onClick={() => toggle(f.id)}
                          className={cn(
                            'cursor-pointer transition-colors hover:bg-secondary',
                            isOpen && 'bg-secondary',
                            focusedFindingId === f.id && 'bg-brand-primary ring-1 ring-inset ring-brand-solid',
                          )}
                        >
                          <td className="pl-3 py-3 align-top">
                            <button
                              type="button"
                              aria-expanded={isOpen}
                              aria-label={`Toggle details for ${f.title}`}
                              onClick={(e) => {
                                e.stopPropagation()
                                toggle(f.id)
                              }}
                              className="rounded p-1 text-quaternary transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
                            >
                              <ChevronRight className={cn('size-4 transition-transform', isOpen && 'rotate-90')} />
                            </button>
                          </td>
                          <td className="px-2 py-3 align-top">
                            <PriorityBadge priority={f.priority} />
                          </td>
                          <td className="px-2 py-3 align-top">
                            <SevBadge sev={f.severity} />
                          </td>
                          <td className="px-4 py-3 align-top">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-semibold text-primary">{f.title}</span>
                              {f.kev && <KevBadge />}
                              {f.kind && f.kind !== 'sca' && <KindBadge kind={f.kind} />}
                              {f.cwe && (
                                <span className="rounded bg-secondary px-1.5 py-0.2 font-mono text-[11px] font-bold tabular-nums text-secondary">
                                  {f.cwe}
                                </span>
                              )}
                              {triage && <AITriageBadges triage={triage} />}
                              {v && !v.direct && v.path.length >= 2 && (
                                <span
                                  className="text-xs text-tertiary"
                                  title={v.path.map(shortPkg).join(' › ')}
                                >
                                  via <span className="font-mono font-medium text-secondary">{shortPkg(v.path[v.path.length - 2])}</span>
                                </span>
                              )}
                            </div>
                            {f.description && !isOpen && (
                              <div className="mt-1 line-clamp-1 text-xs text-tertiary">{f.description}</div>
                            )}
                          </td>
                          <td className="px-4 py-3 align-top">
                            <ScopeBadge scope={f.scope} />
                          </td>
                          <td className="px-4 py-3 align-top" onClick={(e) => e.stopPropagation()}>
                            <FindingStatusControl
                              finding={f}
                              engagementId={engagementId}
                              onUpdated={onUpdated}
                              onReload={onReload}
                            />
                          </td>
                        </tr>
                        {isOpen && (
                          <tr className="bg-secondary border-t border-secondary">
                            <td />
                            <td colSpan={5} className="p-4">
                              <FindingDetail
                                finding={f}
                                vuln={v}
                                engagementId={engagementId}
                                onUpdated={onUpdated}
                                onReload={onReload}
                              />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          <TablePagination
            page={page}
            totalPages={Math.max(1, Math.ceil(rows.length / PAGE_SIZE))}
            total={rows.length}
            pageSize={PAGE_SIZE}
            onPageChange={setPage}
          />
        </Card>
      )}
    </div>
  )
}

/* ==========================================================================
   FindingDetail: 2-Column Balanced Layout (Technical vs Collab)
   ========================================================================== */

export function FindingDetail({
  finding,
  vuln,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  vuln: Vulnerability | undefined
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  return (
    <div className="grid grid-cols-1 items-stretch gap-4 lg:grid-cols-12">
      {/* Left Column (7 cols): Technical Analysis & Remediation Specs */}
      <div className="space-y-3.5 lg:col-span-7">
        {/* Description & Remediation Section */}
        {finding.description && (
          <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs">
            <div className="mb-1 text-xs font-bold uppercase tracking-wider text-secondary">
              Vulnerability Description &amp; Impact
            </div>
            <p className="whitespace-pre-line text-xs leading-relaxed text-secondary font-sans">
              {finding.description}
            </p>
          </div>
        )}

        {/* Advisory & Package Metrics Ribbon */}
        {vuln ? (
          <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
            <div className="text-xs font-bold uppercase tracking-wider text-secondary">
              Advisory &amp; Dependency Metrics
            </div>

            {/* 4-Stat Metric Strip */}
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">CVSS Score</span>
                <div className="mt-0.5 font-mono text-base font-bold tabular-nums text-primary">
                  {vuln.cvssScore > 0 ? vuln.cvssScore.toFixed(1) : '0.0'}
                </div>
              </div>
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">EPSS Score</span>
                <div className="mt-0.5 font-mono text-base font-bold tabular-nums text-primary">
                  {vuln.epss > 0 ? `${(vuln.epss * 100).toFixed(1)}%` : '0.0%'}
                </div>
              </div>
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">Installed</span>
                <div className="mt-0.5 truncate font-mono text-xs font-bold text-primary" title={`${vuln.component}@${vuln.version}`}>
                  {vuln.component}@{vuln.version}
                </div>
              </div>
              <div className="rounded-lg border border-secondary bg-secondary p-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-tertiary">Fixed In</span>
                <div className="mt-0.5 flex items-center gap-1.5 font-mono text-xs font-bold">
                  {vuln.fixedVersion ? (
                    <span className="text-success-primary font-bold">{vuln.fixedVersion}</span>
                  ) : (
                    <span className="text-quaternary font-normal">None</span>
                  )}
                </div>
              </div>
            </div>

            {/* Detection & Path */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-secondary pt-2.5 text-xs">
              <span className="flex items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">Detected By:</span>
                <DetectedBy sources={vuln.sources} />
              </span>
              <span className="flex items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">Confidence:</span>
                <ConfidenceBadge confidence={vuln.confidence} />
              </span>
            </div>

            {vuln.path.length > 1 && (
              <div className="border-t border-secondary pt-2.5 text-xs">
                <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">Dependency Path:</span>
                <div className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-xs text-secondary">
                  {vuln.path.map((p, i) => (
                    <span key={i} className="flex items-center gap-1.5">
                      {i > 0 && <ChevronRight className="size-3 text-fg-quaternary" />}
                      <span className={i === vuln.path.length - 1 ? 'font-bold text-primary' : ''}>
                        {shortPkg(p)}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="rounded-lg border border-secondary bg-primary p-3 text-xs text-tertiary">
            {finding.dedupKey.startsWith('license:')
              ? 'License-policy finding: Review module licensing compliance below.'
              : 'No matching scanner advisory detail found for this finding.'}
          </div>
        )}

        {/* Compliance Controls */}
        <ComplianceChips controls={finding.complianceControls} />

        {/* Evidence Gate for Exploitation findings */}
        {finding.kind === 'exploitation' && (
          <EvidenceGate
            finding={finding}
            engagementId={engagementId}
            onUpdated={onUpdated}
            onReload={onReload}
          />
        )}

        {/* Explain Judgments / AI Analysis */}
        <ExplainJudgments engagementId={engagementId} findingId={finding.id} />
      </div>

      {/* Right Column (5 cols): Collaboration, Assignment & Retests */}
      <div className="space-y-3.5 lg:col-span-5">
        {/* Assignment & Status Box */}
        <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-secondary">
            Triage &amp; Assignment
          </div>
          <AssigneeControl
            finding={finding}
            engagementId={engagementId}
            onUpdated={onUpdated}
            onReload={onReload}
          />
        </div>

        {/* Retests History & Form */}
        <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
          <RetestPanel finding={finding} engagementId={engagementId} onUpdated={onUpdated} />
        </div>

        {/* Comments Thread */}
        <div className="rounded-lg border border-secondary bg-primary p-3.5 shadow-2xs space-y-3">
          <CommentsPanel engagementId={engagementId} findingId={finding.id} />
        </div>
      </div>
    </div>
  )
}

/* ==========================================================================
   Compliance, AI Judgments, and Evidence Gate
   ========================================================================== */

export function frameworkShort(framework: string): string {
  switch (framework) {
    case 'OWASP-2021':
      return 'OWASP'
    case 'PCI-DSS-4.0':
      return 'PCI DSS'
    case 'ISO-27001-2022':
      return 'ISO 27001'
    default:
      return framework
  }
}

export function ComplianceChips({ controls }: { controls: Finding['complianceControls'] }) {
  if (!controls || controls.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="list" aria-label="Compliance controls">
      <CheckVerified01 aria-hidden className="size-3.5 shrink-0 text-fg-tertiary" />
      <span aria-hidden className="text-[11px] font-bold uppercase tracking-wide text-secondary">
        Compliance
      </span>
      {controls.map((c) => (
        <span
          key={`${c.framework}:${c.id}`}
          role="listitem"
          className="inline-flex items-center gap-1.5 rounded-md border border-secondary bg-primary px-2 py-0.5 text-xs text-secondary"
        >
          <span className="text-tertiary">{frameworkShort(c.framework)}</span>
          <span className="font-mono font-bold tabular-nums text-primary">{c.id}</span>
          <span className="text-tertiary">{c.title}</span>
        </span>
      ))}
    </div>
  )
}

export function JudgmentStateBadge({ state }: { state: string }) {
  const tone =
    state === 'confirmed'
      ? 'text-success-primary border-utility-green-300 bg-success-primary'
      : state === 'refuted'
        ? 'text-warning-primary border-utility-orange-300 bg-warning-primary'
        : 'text-tertiary border-secondary bg-secondary'
  return (
    <span className={cn('rounded border px-1.5 py-0.2 text-[10px] font-bold uppercase tracking-wide', tone)}>
      {state}
    </span>
  )
}

export function RiskNarrative({ j }: { j: Judgment }) {
  const c = j.claim as Partial<RiskNarrativeClaim>
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">Risk narrative</span>
        <JudgmentStateBadge state={j.state} />
        {typeof c.priority === 'number' && (
          <span className="font-mono text-xs font-bold tabular-nums text-secondary">priority {c.priority}/5</span>
        )}
      </div>
      {(c.drivers?.length ?? 0) > 0 && (
        <div className="flex flex-wrap gap-1">
          {c.drivers!.map((d) => (
            <span
              key={d}
              className="rounded border border-secondary bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-secondary"
            >
              {d}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function Critique({ j }: { j: Judgment }) {
  const c = j.claim as Partial<CritiqueClaim>
  const verdictTone =
    c.verdict === 'refuted'
      ? 'text-warning-primary'
      : c.verdict === 'sound'
        ? 'text-success-primary'
        : 'text-secondary'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">Critique</span>
        <JudgmentStateBadge state={j.state} />
        {c.verdict && <span className={cn('text-xs font-bold', verdictTone)}>{c.verdict}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {c.driver && <span className="font-mono text-[11px] text-tertiary">{c.driver}</span>}
    </div>
  )
}

export function Reachability({ j }: { j: Judgment }) {
  const c = j.claim as Partial<ReachabilityClaim>
  const tone =
    c.reachable === 'reachable'
      ? 'text-error-primary border-error bg-error-primary'
      : c.reachable === 'not_reachable'
        ? 'text-success-primary border-utility-green-300 bg-success-primary'
        : 'text-tertiary border-secondary bg-secondary'
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-primary">Reachability</span>
        <JudgmentStateBadge state={j.state} />
        {c.reachable && (
          <span className={cn('rounded border px-1.5 py-0.2 text-[10px] font-bold uppercase tracking-wide', tone)}>
            {c.reachable.replace('_', ' ')}
          </span>
        )}
        {c.tier && <span className="font-mono text-[11px] font-bold tabular-nums text-secondary">{c.tier}</span>}
        {typeof c.confidence === 'number' && (
          <span className="font-mono text-xs tabular-nums text-tertiary">{c.confidence}% confidence</span>
        )}
      </div>
      {(c.path?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-1 font-mono text-[11px] tabular-nums text-secondary">
          {c.path!.map((sym, i) => (
            <span key={i} className="flex items-center gap-1">
              {i > 0 && <ChevronRight aria-hidden className="size-3 text-fg-quaternary" />}
              <span>{sym}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function ExplainJudgments({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const { data: judgments } = useFetch(
    () => api.judgments(engagementId).catch(() => [] as Judgment[]),
    { deps: [engagementId] },
  )

  const relevant = (judgments ?? []).filter(
    (j) =>
      j.subjectId === findingId &&
      (j.capability === 'risk_narrative' || j.capability === 'critique' || j.capability === 'reachability'),
  )
  if (relevant.length === 0) return null

  return (
    <div className="space-y-2 rounded-lg border border-secondary bg-primary p-3 shadow-2xs">
      <div className="flex items-center gap-1.5">
        <Stars01 aria-hidden className="size-3.5 text-brand-secondary" />
        <span className="text-[11px] font-bold uppercase tracking-wide text-secondary">AI Triage &amp; Analysis</span>
      </div>
      <ul className="space-y-2.5" role="list">
        {relevant.map((j) => (
          <li key={j.id}>
            {j.capability === 'reachability' ? (
              <Reachability j={j} />
            ) : j.capability === 'critique' ? (
              <Critique j={j} />
            ) : (
              <RiskNarrative j={j} />
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

export const GATED_JUDGMENT_CAPABILITIES = new Set(['reachability', 'sast', 'critique', 'threat', 'vex_justification'])

export function JudgmentClaim({ judgment }: { judgment: Judgment }) {
  if (judgment.capability === 'reachability') return <Reachability j={judgment} />
  if (judgment.capability === 'critique') return <Critique j={judgment} />
  if (judgment.capability === 'risk_narrative') return <RiskNarrative j={judgment} />

  return (
    <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
      {Object.entries(judgment.claim).map(([key, value]) => (
        <div key={key} className="rounded-md border border-secondary bg-secondary px-2.5 py-2">
          <dt className="text-[11px] font-bold uppercase tracking-wide text-tertiary">{key.replaceAll('_', ' ')}</dt>
          <dd className="mt-0.5 break-words font-mono text-primary">
            {Array.isArray(value) ? value.join(', ') : String(value ?? 'None')}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function sealedJudgmentId(item: EvidenceItem): string {
  if (item.kind !== 'judgment_proposed' || !item.contentBase64) return ''
  try {
    const bytes = Uint8Array.from(atob(item.contentBase64), (c) => c.charCodeAt(0))
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as unknown
    if (payload && typeof payload === 'object' && 'judgment_id' in payload) {
      const id = (payload as { judgment_id?: unknown }).judgment_id
      return typeof id === 'string' ? id : ''
    }
  } catch {
    // A malformed ledger item must not hide the rest of the review queue.
  }
  return ''
}

export const EVIDENCE_BAR = 75

function EvidenceGate({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [open, setOpen] = useState(false)
  const [score, setScore] = useState(90)
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const proven = finding.evidenceScore >= EVIDENCE_BAR

  async function submit() {
    setBusy(true)
    setErr('')
    try {
      onUpdated(await api.verifyFinding(engagementId, finding.id, score, rationale.trim(), finding.version))
      setOpen(false)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setErr('This finding changed: reloading latest state.')
        onReload()
      } else {
        setErr(e instanceof ApiError ? e.message : 'Verify failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-secondary bg-primary p-3 shadow-2xs">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        <span className="flex items-center gap-1.5">
          {proven ? (
            <ShieldTick className="size-4 text-success-primary" />
          ) : (
            <Shield01 className="size-4 text-warning-primary" />
          )}
          <span className={cn('font-semibold', proven ? 'text-success-primary' : 'text-warning-primary')}>
            {proven ? 'Verified (Reportable)' : 'Unproven (Not reportable)'}
          </span>
        </span>
        <DetailKV label="evidence" value={`${finding.evidenceScore}/${EVIDENCE_BAR}`} valueClass="font-mono font-bold tabular-nums" />
        {finding.proposedBy && <DetailKV label="proposed by" value={finding.proposedBy} />}
      </div>

      {!proven && (
        <div className="mt-2">
          {!open ? (
            <Button variant="secondary" onClick={() => setOpen(true)} className="px-2.5 py-1 text-xs">
              <ShieldTick className="size-3.5" /> Verify finding
            </Button>
          ) : (
            <div className="space-y-2">
              <p className="text-[11px] text-tertiary">
                Record an adversarial verdict. The verifier must be a different person than the proposer; the verdict is
                sealed into the evidence chain. A score ≥ {EVIDENCE_BAR} makes it promotable.
              </p>
              <label htmlFor="evidence-score-input" className="flex items-center gap-2 text-xs">
                <span className="text-secondary font-medium">Score</span>
                <input
                  id="evidence-score-input"
                  type="number"
                  min={0}
                  max={100}
                  value={score}
                  onChange={(e) => setScore(Math.max(0, Math.min(100, Number(e.target.value))))}
                  className="w-20 rounded-md border border-secondary bg-secondary px-2 py-1 font-mono tabular-nums text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
                />
              </label>
              <textarea
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Rationale (how it was reproduced / refuted)"
                aria-label="Verdict rationale"
                rows={2}
                className="w-full rounded-md border border-secondary bg-secondary px-2.5 py-1.5 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
              />
              {err && <p className="text-xs text-error-primary">{err}</p>}
              <div className="flex gap-2">
                <Button loading={busy} onClick={submit} className="px-2.5 py-1 text-xs">
                  Seal verdict
                </Button>
                <Button variant="ghost" onClick={() => setOpen(false)} className="px-2.5 py-1 text-xs">
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function DetailKV({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-[11px] font-bold uppercase tracking-wide text-tertiary">{label}:</span>
      <span className={cn('font-semibold text-primary', valueClass)}>{value}</span>
    </span>
  )
}

export const FINDING_STATUSES = ['open', 'triage', 'confirmed', 'false_positive', 'remediated']

export const STATUS_DOT: Record<string, string> = {
  open: 'bg-utility-gray-400',
  triage: 'bg-utility-orange-500',
  confirmed: 'bg-utility-red-500',
  false_positive: 'bg-utility-gray-300',
  remediated: 'bg-utility-green-500',
}

export const STATUS_TEXT: Record<string, string> = {
  open: 'text-secondary',
  triage: 'text-warning-primary',
  confirmed: 'text-error-primary',
  false_positive: 'text-tertiary',
  remediated: 'text-success-primary',
}

export function StatusLabel({ status }: { status: string }) {
  return (
    <span className={cn('flex items-center gap-2 font-medium', STATUS_TEXT[status] ?? 'text-tertiary')}>
      <span className={cn('size-2 shrink-0 rounded-full', STATUS_DOT[status] ?? 'bg-utility-gray-400')} />
      {statusLabel(status)}
    </span>
  )
}

export function FindingStatusControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'failed' | 'conflict'>('')

  async function change(status: string) {
    if (status === finding.status) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.updateFindingStatus(engagementId, finding.id, status, finding.version))
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload()
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Select
        value={finding.status}
        onValueChange={change}
        disabled={busy}
        size="sm"
        ariaLabel={`Triage status for ${finding.title}`}
        className="min-w-[9.5rem]"
        options={FINDING_STATUSES.map((s) => ({ value: s, label: <StatusLabel status={s} /> }))}
      />
      {busy && <Loading01 className="size-3.5 shrink-0 animate-spin text-tertiary" />}
      {note === 'failed' && <span className="text-xs text-error-primary">failed</span>}
      {note === 'conflict' && (
        <span className="inline-flex items-center gap-1 text-xs font-medium text-warning-primary">
          <AlertTriangle className="size-3" /> reloaded
        </span>
      )}
    </div>
  )
}

/* ==========================================================================
   Collaboration Panels: Assignee, Retest, Comments
   ========================================================================== */

export function AssigneeControl({
  finding,
  engagementId,
  onUpdated,
  onReload,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
}) {
  const [value, setValue] = useState(finding.assignee)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<'' | 'saved' | 'failed' | 'conflict'>('')

  useEffect(() => {
    setValue(finding.assignee)
  }, [finding.assignee, finding.version])

  async function save() {
    if (value.trim() === finding.assignee) return
    setBusy(true)
    setNote('')
    try {
      onUpdated(await api.setFindingAssignee(engagementId, finding.id, value.trim(), finding.version))
      setNote('saved')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setNote('conflict')
        onReload()
      } else {
        setNote('failed')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-secondary">
        <User01 className="size-3.5 text-fg-tertiary" />
        <span>Assignee:</span>
      </div>
      <div className="flex items-center gap-2">
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onBlur={save}
          placeholder="unassigned"
          aria-label={`Assignee for ${finding.title}`}
          className="h-8 max-w-[12rem] text-xs font-medium"
        />
        {busy && <Loading01 className="size-3.5 animate-spin text-tertiary" />}
        {note === 'saved' && <span className="text-xs font-bold text-success-primary">saved</span>}
        {note === 'failed' && <span className="text-xs font-bold text-error-primary">failed</span>}
        {note === 'conflict' && (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-warning-primary">
            <AlertTriangle className="size-3" /> reloaded
          </span>
        )}
      </div>
    </div>
  )
}

export const RETEST_OUTCOMES: { value: RetestOutcome; label: string }[] = [
  { value: 'remediated', label: 'Remediated' },
  { value: 'still_vulnerable', label: 'Still vulnerable' },
  { value: 'not_reproducible', label: 'Not reproducible' },
]

export function RetestOutcomeBadge({ outcome }: { outcome: RetestOutcome }) {
  const tone: Record<RetestOutcome, string> = {
    remediated: 'bg-success-primary text-success-primary border-utility-green-300',
    still_vulnerable: 'bg-error-primary text-error-primary border-error',
    not_reproducible: 'bg-secondary text-tertiary border-secondary',
  }
  const label: Record<RetestOutcome, string> = {
    remediated: 'Remediated',
    still_vulnerable: 'Still vuln',
    not_reproducible: 'Not repro',
  }
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.2 text-[10px] font-bold uppercase', tone[outcome])}>
      {label[outcome]}
    </span>
  )
}

export function RetestPanel({
  finding,
  engagementId,
  onUpdated,
}: {
  finding: Finding
  engagementId: string
  onUpdated: (f: Finding) => void
}) {
  const [list, setList] = useState<Retest[]>([])
  const [outcome, setOutcome] = useState<RetestOutcome>('remediated')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useFetch(
    () => api.findingRetests(engagementId, finding.id).then((r) => { setList(r); return r }).catch(() => [] as Retest[]),
    { deps: [engagementId, finding.id] },
  )

  async function submit() {
    setBusy(true)
    setErr(null)
    try {
      const { retest, finding: updated } = await api.recordRetest(engagementId, finding.id, outcome, note, finding.version)
      setList((prev) => [...prev, retest])
      setNote('')
      onUpdated(updated)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setErr('Finding changed: reload and retry.')
      else setErr(e instanceof Error ? e.message : 'Failed to record retest')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
        <RefreshCcw01 className="size-3.5 text-fg-tertiary" />
        <span>Retests &amp; Verification</span>
      </div>

      {list.length > 0 && (
        <ul className="space-y-1.5 rounded-lg border border-secondary bg-secondary p-2">
          {list.map((r) => (
            <li key={r.id} className="flex items-center gap-2 text-xs">
              <RetestOutcomeBadge outcome={r.outcome} />
              <span className="font-semibold text-primary">{r.tester}</span>
              {r.note && <span className="truncate text-tertiary">({r.note})</span>}
              <span className="ml-auto shrink-0 tabular-nums text-quaternary">
                {r.at ? new Date(r.at).toLocaleDateString() : ''}
              </span>
            </li>
          ))}
        </ul>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={outcome}
          onValueChange={(v) => setOutcome(v as RetestOutcome)}
          ariaLabel="Retest outcome"
          size="sm"
          options={RETEST_OUTCOMES.map((o) => ({ value: o.value, label: o.label }))}
        />
        <Input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="note (optional)"
          className="h-8 flex-1 text-xs"
        />
        <Button loading={busy} onClick={submit} className="h-8 px-3 text-xs font-semibold">
          Record
        </Button>
      </div>
      {err && <p className="text-xs text-error-primary">{err}</p>}
    </div>
  )
}

export function CommentsPanel({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const [comments, setComments] = useState<FindingComment[] | null>(null)
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const { refetch: reload } = useFetch(
    () => api.findingComments(engagementId, findingId).then((c) => { setComments(c); return c }).catch(() => { setComments([]); return [] }),
    { deps: [engagementId, findingId] },
  )

  async function add() {
    if (!body.trim()) return
    setBusy(true)
    setErr(null)
    try {
      await api.addFindingComment(engagementId, findingId, body.trim())
      setBody('')
      reload()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to add comment')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
        <MessageSquare01 className="size-3.5 text-fg-tertiary" />
        <span>Comments</span>
      </div>

      <div className="space-y-1.5 max-h-48 overflow-y-auto">
        {comments === null ? (
          <span className="text-xs text-quaternary">Loading...</span>
        ) : comments.length === 0 ? (
          <span className="text-xs text-quaternary">No comments yet.</span>
        ) : (
          comments.map((c) => (
            <div key={c.id} className="rounded-lg border border-secondary bg-secondary px-3 py-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-primary">{c.author}</span>
                <span className="text-[11px] text-quaternary">
                  {c.createdAt ? new Date(c.createdAt).toLocaleString() : ''}
                </span>
              </div>
              <p className="mt-1 whitespace-pre-line text-secondary">{c.body}</p>
            </div>
          ))
        )}
      </div>

      <div className="flex items-center gap-2">
        <Input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing && !busy) add()
          }}
          placeholder="Add a comment..."
          aria-label="New comment"
          className="h-8 flex-1 text-xs"
        />
        <Button loading={busy} onClick={add} variant="secondary" className="h-8 px-3 text-xs font-semibold">
          Post
        </Button>
      </div>
      {err && <p className="mt-1 text-xs text-error-primary">{err}</p>}
    </div>
  )
}

/* ==========================================================================
   New Finding Creation Modal Form
   ========================================================================== */

export const WRITEUP_NONE = '__none__'

const CVSS_METRICS: { key: string; label: string; options: { v: string; l: string }[] }[] = [
  { key: 'AV', label: 'Attack Vector', options: [{ v: 'N', l: 'Network' }, { v: 'A', l: 'Adjacent' }, { v: 'L', l: 'Local' }, { v: 'P', l: 'Physical' }] },
  { key: 'AC', label: 'Attack Complexity', options: [{ v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'PR', label: 'Privileges Req.', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'UI', label: 'User Interaction', options: [{ v: 'N', l: 'None' }, { v: 'R', l: 'Required' }] },
  { key: 'S', label: 'Scope', options: [{ v: 'U', l: 'Unchanged' }, { v: 'C', l: 'Changed' }] },
  { key: 'C', label: 'Confidentiality', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'I', label: 'Integrity', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
  { key: 'A', label: 'Availability', options: [{ v: 'N', l: 'None' }, { v: 'L', l: 'Low' }, { v: 'H', l: 'High' }] },
]

function NewFindingModal({ engagementId, onCreated, onCancel }: { engagementId: string; onCreated: () => void; onCancel: () => void }) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [cwe, setCwe] = useState('')
  const [vector, setVector] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [writeups, setWriteups] = useState<Writeup[]>([])
  const [writeupId, setWriteupId] = useState(WRITEUP_NONE)

  useFetch(
    () => api.writeups().then((w) => { setWriteups(w); return w }).catch(() => [] as Writeup[]),
    { deps: [] },
  )

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onCancel])

  function applyWriteup(id: string) {
    setWriteupId(id)
    const w = writeups.find((x) => x.id === id)
    if (!w) return
    setTitle(w.title)
    setSeverity(w.severity)
    setCwe(w.cwe)
    setDescription(w.remediation ? `${w.description}\n\nRemediation:\n${w.remediation}` : w.description)
  }

  async function submit() {
    if (!title.trim()) {
      setErr('Title is required.')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      await api.createFinding(engagementId, { title, description, severity, cvssVector: vector, cwe })
      onCreated()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to create finding')
    } finally {
      setBusy(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop overlay */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onCancel}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-finding-modal-title"
        className="relative z-10 w-full max-w-xl max-h-[90vh] flex flex-col rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4">
          <h2 id="new-finding-modal-title" className="text-base font-bold text-primary flex items-center gap-2">
            <Plus className="size-4 text-brand-secondary" />
            <span>New finding</span>
          </h2>
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg p-1.5 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
            aria-label="Close modal"
          >
            <XClose className="size-4" />
          </button>
        </div>

        {/* Scrollable Form Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {writeups.length > 0 && (
            <div>
              <label htmlFor="nf-template" className="block text-xs font-semibold text-secondary mb-1.5">
                Start from template <span className="font-normal text-quaternary">(optional)</span>
              </label>
              <Select
                id="nf-template"
                value={writeupId}
                onValueChange={applyWriteup}
                ariaLabel="Insert a finding writeup template"
                className="w-full"
                options={[
                  { value: WRITEUP_NONE, label: <span className="text-tertiary">Blank finding template...</span> },
                  ...writeups.map((w) => ({
                    value: w.id,
                    label: (
                      <span className="flex items-center gap-2">
                        <span className="text-[10px] font-bold uppercase tracking-wide text-quaternary">{w.category}</span>
                        {w.title}
                      </span>
                    ),
                  })),
                ]}
              />
            </div>
          )}

          <div>
            <label htmlFor="nf-title" className="block text-xs font-semibold text-secondary mb-1.5">
              Title <span className="text-error-primary">*</span>
            </label>
            <Input
              id="nf-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Reflected XSS in search endpoint"
              className="h-9 w-full text-xs"
            />
          </div>

          <div>
            <label htmlFor="nf-desc" className="block text-xs font-semibold text-secondary mb-1.5">
              Description &amp; Remediation
            </label>
            <textarea
              id="nf-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full rounded-lg border border-secondary bg-secondary px-3.5 py-2 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid resize-none"
              placeholder="Impact, reproduction steps, remediation guidance..."
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold text-secondary mb-1.5">
                Severity {vector.trim() && <span className="font-normal text-quaternary">(from CVSS)</span>}
              </label>
              <Select
                value={severity}
                onValueChange={setSeverity}
                disabled={Boolean(vector.trim())}
                ariaLabel="Severity"
                className="w-full"
                options={['critical', 'high', 'medium', 'low', 'info'].map((s) => ({
                  value: s,
                  label: (
                    <span className="flex items-center gap-2">
                      <span className={cn('size-2 rounded-full', STATUS_DOT[s] ?? 'bg-utility-gray-400')} />
                      <span className="capitalize">{s}</span>
                    </span>
                  ),
                }))}
              />
            </div>

            <div>
              <label htmlFor="nf-cwe" className="block text-xs font-semibold text-secondary mb-1.5">
                CWE Identifier
              </label>
              <Input
                id="nf-cwe"
                value={cwe}
                onChange={(e) => setCwe(e.target.value)}
                placeholder="e.g. CWE-79"
                className="h-9 w-full text-xs"
              />
            </div>
          </div>

          <CvssCalculator vector={vector} onChange={setVector} onSeverityChange={setSeverity} />

          {err && <p className="text-xs font-semibold text-error-primary">{err}</p>}
        </div>

        {/* Footer: Single primary action button only (per DESIGN-REFERENCE.md modal rule) */}
        <div className="flex items-center justify-end border-t border-secondary px-6 py-4 bg-secondary">
          <Button variant="primary" loading={busy} onClick={submit} className="h-9 px-5 text-xs font-semibold">
            <Plus className="size-4" /> Create finding
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

function CvssCalculator({
  vector,
  onChange,
  onSeverityChange,
}: {
  vector: string
  onChange: (v: string) => void
  onSeverityChange: (s: Severity) => void
}) {
  const [enabled, setEnabled] = useState(Boolean(vector.trim()))
  const [metrics, setMetrics] = useState<Record<string, string>>(() => ({
    AV: 'N',
    AC: 'L',
    PR: 'N',
    UI: 'N',
    S: 'U',
    C: 'H',
    I: 'H',
    A: 'H',
  }))
  const [preview, setPreview] = useState<{ score: number; severity: string } | null>(null)
  const [scoring, setScoring] = useState(false)
  const [failed, setFailed] = useState(false)

  const built = useMemo(() => {
    if (!enabled) return ''
    const parts = CVSS_METRICS.map((m) => `${m.key}:${metrics[m.key] || m.options[0].v}`)
    return `CVSS:3.1/${parts.join('/')}`
  }, [enabled, metrics])

  useEffect(() => {
    if (!enabled || !built) return
    let live = true
    setScoring(true)
    setFailed(false)
    api
      .cvssScore(built)
      .then((res) => {
        if (!live) return
        setPreview(res)
        setScoring(false)
        onChange(built)
        if (res.severity) onSeverityChange(res.severity.toLowerCase() as Severity)
      })
      .catch(() => {
        if (live) {
          setPreview(null)
          setFailed(true)
          setScoring(false)
        }
      })
    return () => {
      live = false
    }
  }, [built, enabled, onChange, onSeverityChange])

  function toggle(on: boolean) {
    setEnabled(on)
    if (!on) {
      onChange('')
      setPreview(null)
      setFailed(false)
      setScoring(false)
    }
  }

  return (
    <div className="rounded-lg border border-secondary bg-primary p-3">
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} className="size-4 accent-brand-solid" />
        <span className="font-semibold text-primary">Score with CVSS v3.1 Calculator</span>
        {scoring ? (
          <Loading01 className="ml-auto size-4 animate-spin text-tertiary" />
        ) : failed ? (
          <span className="ml-auto text-xs text-error-primary font-semibold">score unavailable</span>
        ) : preview ? (
          <span className="ml-auto font-mono text-sm tabular-nums">
            <span className={cn('font-bold', sevText[preview.severity as Severity] ?? 'text-primary')}>
              {preview.score.toFixed(1)}
            </span>{' '}
            <span className="text-secondary font-semibold capitalize">({preview.severity})</span>
          </span>
        ) : null}
      </label>
      {enabled && (
        <>
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {CVSS_METRICS.map((m) => (
              <div key={m.key}>
                <label className="block text-[11px] font-semibold text-secondary mb-1">
                  {m.label}
                </label>
                <Select
                  size="sm"
                  value={metrics[m.key]}
                  onValueChange={(v) => setMetrics((cur) => ({ ...cur, [m.key]: v }))}
                  ariaLabel={m.label}
                  className="w-full"
                  options={m.options.map((o) => ({ value: o.v, label: o.l }))}
                />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
