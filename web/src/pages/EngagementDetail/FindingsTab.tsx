import { CheckCircle, File06, Plus, SearchLg, XClose } from '@untitledui/icons'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Button, Card, EmptyState, Select, Spinner, cn } from '../../components/ui'
import { findingKindLabel } from '../../lib/format'
import type { Finding, ScanResult, Severity, Vulnerability } from '../../lib/types'
import { vulnKey, shortPkg } from './VulnsTab'
import {
  DEFAULT_PAGE_SIZE,
  FindingsTable,
  INITIAL_DIRECTION,
  PAGE_SIZE_OPTIONS,
  TablePagination,
  findingAnchor,
  isFindingSortKey,
  sortFindings,
  type FindingSortKey,
  type SortDirection,
} from './components/FindingsTable'
import { STATUS_DOT } from './components/FindingStatus'
import { NewFindingModal } from './components/NewFindingModal'

// Re-export shared symbols consumed by sibling tabs (ReviewsTab) and detail views.
export {
  EVIDENCE_BAR,
  GATED_JUDGMENT_CAPABILITIES,
  JudgmentClaim,
  JudgmentStateBadge,
  sealedJudgmentId,
} from './components/FindingJudgments'
export { FindingDetail } from './components/FindingDetail'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

function isSeverityFilter(value: string | null): value is Severity | 'all' {
  return value === 'all' || (value !== null && (SEVERITIES as readonly string[]).includes(value))
}

/**
 * Everything a search should reach for one row. The placeholder promises CVE,
 * CWE and package, so the package name, its dependency path, the CVE id and the
 * priority label are indexed alongside the title and description.
 */
export function findingSearchIndex(finding: Finding, vuln: Vulnerability | undefined): string {
  const parts = [
    finding.title,
    finding.description,
    finding.cwe,
    finding.assignee,
    finding.scope,
    finding.kind,
    // The dedup key carries the rule or advisory identity, e.g.
    // sca:CVE-2020-7774:yargs-parser.
    finding.dedupKey,
    `P${finding.priority}`,
  ]
  if (vuln) {
    parts.push(vuln.id, vuln.component, shortPkg(vuln.component), vuln.version, vuln.ecosystem ?? '')
    parts.push(...vuln.path, ...vuln.path.map(shortPkg))
  }
  return parts.filter(Boolean).join(' ').toLowerCase()
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
  readOnly = false,
  readOnlyReason,
}: {
  findings: Finding[] | null
  scan: ScanResult | null
  engagementId: string
  filter: Severity | 'all'
  setFilter: (v: Severity | 'all') => void
  focusedFindingId: string
  onUpdated: (f: Finding) => void
  onReload: () => void
  /** Archived engagements accept no writes. */
  readOnly?: boolean
  readOnlyReason?: string
}) {
  const [params, setParams] = useSearchParams()
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [creating, setCreating] = useState(false)

  // Filters, sort and paging live in the query string so a shared link keeps them.
  const searchQuery = params.get('q') ?? ''
  const kindFilter = params.get('kind') ?? 'all'
  const sortParam = params.get('sort')
  const sortKey: FindingSortKey | null = isFindingSortKey(sortParam) ? sortParam : null
  const sortDirection: SortDirection = params.get('dir') === 'desc' ? 'desc' : 'asc'
  const sizeParam = Number(params.get('size'))
  const pageSize = (PAGE_SIZE_OPTIONS as readonly number[]).includes(sizeParam) ? sizeParam : DEFAULT_PAGE_SIZE
  const page = Math.max(1, Number(params.get('fpage')) || 1)

  const patch = useCallback(
    (next: Record<string, string | null>) => {
      setParams(
        (current) => {
          const updated = new URLSearchParams(current)
          for (const [key, value] of Object.entries(next)) {
            if (value === null || value === '') updated.delete(key)
            else updated.set(key, value)
          }
          return updated
        },
        { replace: true },
      )
    },
    [setParams],
  )

  // The severity filter is shared with the Overview cards, which set it through
  // the parent. A link's severity wins on arrival, the parent state afterwards.
  const urlSeverity = params.get('sev')
  useEffect(() => {
    if (isSeverityFilter(urlSeverity) && urlSeverity !== filter) setFilter(urlSeverity)
    // Mount only: adopting the link's severity, not tracking it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useEffect(() => {
    if ((params.get('sev') ?? 'all') !== filter) patch({ sev: filter === 'all' ? null : filter, fpage: null })
  }, [filter, params, patch])

  // Separate actionable third-party findings from first-party historical advisories.
  const thirdParty = useMemo(
    () => (findings ?? []).filter((f) => f.class !== 'first_party_historical'),
    [findings],
  )
  const historical = useMemo(
    () => (findings ?? []).filter((f) => f.class === 'first_party_historical'),
    [findings],
  )
  // The Kind filter only appears when there's more than one to choose from.
  const kinds = useMemo(
    () => Array.from(new Set(thirdParty.map((f) => f.kind).filter(Boolean))),
    [thirdParty],
  )

  const vulnByKey = useMemo(() => {
    const m = new Map<string, Vulnerability>()
    for (const v of scan?.vulnerabilities ?? []) m.set(vulnKey(v), v)
    return m
  }, [scan])

  const searchIndex = useMemo(() => {
    const index = new Map<string, string>()
    for (const finding of thirdParty) {
      index.set(finding.id, findingSearchIndex(finding, vulnByKey.get(finding.dedupKey)))
    }
    return index
  }, [thirdParty, vulnByKey])

  // Filter rows by severity, kind, and search query, then sort.
  const rows = useMemo(() => {
    const q = searchQuery.toLowerCase().trim()
    const filtered = thirdParty.filter((f) => {
      const matchSeverity = filter === 'all' || f.severity === filter
      const matchKind = kindFilter === 'all' || f.kind === kindFilter
      const matchSearch = !q || (searchIndex.get(f.id) ?? '').includes(q)
      return matchSeverity && matchKind && matchSearch
    })
    return sortFindings(filtered, sortKey, sortDirection)
  }, [thirdParty, filter, kindFilter, searchQuery, searchIndex, sortKey, sortDirection])

  useEffect(() => {
    if (!focusedFindingId || findings === null) return
    const idx = rows.findIndex((f) => f.id === focusedFindingId)
    if (idx >= 0) {
      const targetPage = Math.floor(idx / pageSize) + 1
      if (targetPage !== page) patch({ fpage: targetPage === 1 ? null : String(targetPage) })
    }
    // Bail out when already expanded so this never feeds a re-render cycle.
    setExpanded((current) => (current.has(focusedFindingId) ? current : new Set(current).add(focusedFindingId)))
    const frame = requestAnimationFrame(() => {
      document.getElementById(findingAnchor(focusedFindingId))?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    })
    return () => cancelAnimationFrame(frame)
  }, [findings, focusedFindingId, rows, page, pageSize, patch])

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

  function onSort(key: FindingSortKey) {
    const nextDirection: SortDirection =
      sortKey === key ? (sortDirection === 'asc' ? 'desc' : 'asc') : INITIAL_DIRECTION[key]
    patch({ sort: key, dir: nextDirection, fpage: null })
  }

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize))
  const safePage = Math.min(page, totalPages)

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
                onChange={(e) => patch({ q: e.target.value, fpage: null })}
                placeholder="Search findings, CVE, CWE, package..."
                aria-label="Search findings"
                className="h-9 w-full rounded-lg border border-secondary bg-primary pl-9 pr-8 text-xs text-primary placeholder:text-quaternary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-solid"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => patch({ q: null, fpage: null })}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-quaternary hover:text-primary"
                  title="Clear search"
                  aria-label="Clear search"
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
                      <span className="size-2 rounded-full bg-utility-neutral-400" />
                      <span>All Severities</span>
                    </span>
                  ),
                },
                ...SEVERITIES.map((s) => ({
                  value: s,
                  label: (
                    <span className="flex items-center gap-2">
                      <span className={cn('size-2 rounded-full', STATUS_DOT[s] ?? 'bg-utility-neutral-400')} />
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
                onValueChange={(v) => patch({ kind: v === 'all' ? null : v, fpage: null })}
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
            <span title={readOnly ? readOnlyReason : undefined}>
              <Button
                variant="secondary"
                disabled={readOnly}
                aria-describedby={readOnly ? 'findings-read-only' : undefined}
                onClick={() => setCreating((c) => !c)}
                className="inline-flex items-center gap-1.5 h-9 px-3.5 text-xs font-semibold"
              >
                <Plus className="size-4" />
                <span>New finding</span>
              </Button>
            </span>
          </div>
        </div>
        {readOnly && readOnlyReason && (
          <p id="findings-read-only" className="mt-2 text-xs text-tertiary">
            {readOnlyReason}
          </p>
        )}
      </Card>

      {/* Creation Modal */}
      {creating && !readOnly && (
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
            <FindingsTable
              rows={rows}
              page={safePage}
              pageSize={pageSize}
              sortKey={sortKey}
              sortDirection={sortDirection}
              onSort={onSort}
              expanded={expanded}
              focusedFindingId={focusedFindingId}
              vulnByKey={vulnByKey}
              triageByKey={triageByKey}
              engagementId={engagementId}
              onToggle={toggle}
              onUpdated={onUpdated}
              onReload={onReload}
              readOnly={readOnly}
              readOnlyReason={readOnlyReason}
            />
          )}

          <TablePagination
            page={safePage}
            totalPages={totalPages}
            total={rows.length}
            pageSize={pageSize}
            onPageChange={(p) => patch({ fpage: p === 1 ? null : String(p) })}
            onPageSizeChange={(size) => patch({ size: String(size), fpage: null })}
          />
        </Card>
      )}
    </div>
  )
}
