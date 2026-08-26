import { CheckCircle, File06, Plus, SearchLg, XClose } from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { Button, Card, EmptyState, Select, Spinner, cn } from '../../components/ui'
import { findingKindLabel } from '../../lib/format'
import type { Finding, ScanResult, Severity, Vulnerability } from '../../lib/types'
import { vulnKey } from './VulnsTab'
import { FindingsTable, PAGE_SIZE, TablePagination, findingAnchor } from './components/FindingsTable'
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

  // Filter rows by severity, kind, and search query.
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
    // Bail out when already expanded so this never feeds a re-render cycle.
    setExpanded((current) => (current.has(focusedFindingId) ? current : new Set(current).add(focusedFindingId)))
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
            <FindingsTable
              rows={rows}
              page={page}
              expanded={expanded}
              focusedFindingId={focusedFindingId}
              vulnByKey={vulnByKey}
              triageByKey={triageByKey}
              engagementId={engagementId}
              onToggle={toggle}
              onUpdated={onUpdated}
              onReload={onReload}
            />
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
