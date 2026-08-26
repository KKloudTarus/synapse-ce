import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Copy01,
  File02,
  FilterLines,
  FolderClosed,
  LayersThree01,
  LinkExternal02,
  SearchLg as Search,
  Shield01,
  ShieldTick,
  ShieldZap,
  Tool01,
  Virus,
  XClose,
} from '@untitledui/icons'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Button, EmptyState, ErrorState, Field, Pill, Select, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import { projectCodePath } from '../../lib/projectCodeNavigation'
import {
  canTransitionIssue,
  ISSUE_STATUSES,
  issueStatusLabel,
  type IssueListFilter,
  type IssuePage,
  type IssueStatus,
  type ProjectIssue,
  type RuleType,
  type Severity,
} from '../../lib/types'
import { useProjectRouteContext } from './CodeQualityProject'

function typeMeta(t: RuleType) {
  switch (t) {
    case 'vulnerability':
      return {
        label: 'Security',
        icon: ShieldTick,
        tone: 'text-error-primary',
        badge: 'bg-error-primary/10 text-error-primary border-error-primary/25',
      }
    case 'bug':
      return {
        label: 'Reliability',
        icon: Virus,
        tone: 'text-warning-primary',
        badge: 'bg-warning-primary/10 text-warning-primary border-warning-primary/25',
      }
    case 'code_smell':
    default:
      return {
        label: 'Maintainability',
        icon: Tool01,
        tone: 'text-utility-blue-600 dark:text-utility-blue-400',
        badge: 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200',
      }
  }
}

function severityBadge(sev: Severity) {
  switch (sev) {
    case 'blocker':
    case 'critical':
      return 'bg-error-primary/10 text-error-primary border-error-primary/25'
    case 'high':
    case 'major':
      return 'bg-utility-orange-50 text-utility-orange-700 dark:bg-utility-orange-950/40 dark:text-utility-orange-300 border-utility-orange-200'
    case 'medium':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'low':
    case 'minor':
    case 'info':
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

function statusBadge(st: IssueStatus) {
  switch (st) {
    case 'open':
      return 'bg-warning-primary/10 text-warning-primary border-warning-primary/25'
    case 'accepted':
      return 'bg-utility-blue-50 text-utility-blue-700 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 border-utility-blue-200'
    case 'false_positive':
      return 'bg-success-primary/10 text-success-primary border-success-primary/25'
    case 'wont_fix':
      return 'bg-secondary text-tertiary border-secondary'
    default:
      return 'bg-secondary text-secondary border-secondary'
  }
}

function cleanIssueTitle(title: string): string {
  if (!title) return ''
  return title.replace(/\s*\([^)]+:\d+\)$/, '')
}

function extractLine(location: string): string | null {
  const match = /:(\d+)$/.exec(location)
  return match ? match[1] : null
}

function groupIssuesByFile(issues: ProjectIssue[]) {
  const groups: Record<string, ProjectIssue[]> = {}
  for (const it of issues) {
    const file = it.file || it.location.split(':')[0] || 'General'
    if (!groups[file]) groups[file] = []
    groups[file].push(it)
  }
  return groups
}

const DEFAULT_FILE_LIMIT = 5

export function ProjectIssuesPage() {
  const { projectKey } = useProjectRouteContext()
  const [params, setParams] = useSearchParams()

  const status = (params.get('status') as IssueStatus) || undefined
  const type = (params.get('type') as RuleType) || undefined
  const severity = (params.get('severity') as any) || undefined
  const language = params.get('language') || undefined
  const search = params.get('search') || undefined
  const newCode = params.get('new_code') === 'true'
  const selectedId = params.get('id')

  const filter = useMemo<IssueListFilter>(
    () => ({ status, type, severity, language, search, newCode, limit: 100 }),
    [status, type, severity, language, search, newCode],
  )

  const [page, setPage] = useState<IssuePage | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [searchInput, setSearchInput] = useState(search ?? '')

  // View & Collapse controls
  const [viewMode, setViewMode] = useState<'grouped' | 'flat'>('grouped')
  const [collapsedFiles, setCollapsedFiles] = useState<Record<string, boolean>>({})
  const [expandedFileLimits, setExpandedFileLimits] = useState<Record<string, boolean>>({})

  const { data: initialPage, loading: initialLoading, error: fetchError } = useFetch(
    () => api.listProjectIssues(projectKey, filter),
    { deps: [projectKey, filter, refresh] },
  )

  useEffect(() => {
    if (initialPage) setPage(initialPage)
  }, [initialPage])

  useEffect(() => {
    if (fetchError) setError(fetchError)
  }, [fetchError])

  useEffect(() => {
    setSearchInput(search ?? '')
  }, [search])

  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== (search ?? '')) {
        patch('search', searchInput || null)
      }
    }, 250)
    return () => clearTimeout(timer)
  }, [searchInput, search])

  function patch(key: string, value: string | null) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  function clearAllFilters() {
    const next = new URLSearchParams()
    if (params.get('id')) next.set('id', params.get('id')!)
    setParams(next, { replace: true })
  }

  const selected = page?.items.find((i) => i.id === selectedId) ?? null
  const groupedIssues = useMemo(() => groupIssuesByFile(page?.items || []), [page?.items])
  const filePaths = Object.keys(groupedIssues)
  const hasActiveFilters = Boolean(status || type || severity || language || search || newCode)

  const vulnCount = page?.facets?.types?.vulnerability || 0
  const bugCount = page?.facets?.types?.bug || 0
  const codeSmellCount = page?.facets?.types?.code_smell || 0

  function toggleFileCollapse(filePath: string) {
    setCollapsedFiles((prev) => ({ ...prev, [filePath]: !prev[filePath] }))
  }

  function collapseAll() {
    const next: Record<string, boolean> = {}
    for (const f of filePaths) next[f] = true
    setCollapsedFiles(next)
  }

  function expandAll() {
    setCollapsedFiles({})
  }

  function toggleFileLimit(filePath: string) {
    setExpandedFileLimits((prev) => ({ ...prev, [filePath]: !prev[filePath] }))
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Top Pillar KPI Bar */}
      {page?.summary && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex flex-wrap items-center gap-6">
            {/* Total */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <Tool01 className="size-5 text-primary" aria-hidden="true" />
              </span>
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-tertiary">Total Issues</div>
                <div className="font-mono text-2xl font-extrabold tabular-nums text-primary">{page.summary.total}</div>
              </div>
            </div>

            <div className="hidden h-8 w-px bg-secondary sm:block" />

            {/* Security */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <ShieldTick className="size-5 text-error-primary" aria-hidden="true" />
              </span>
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-tertiary">Security</div>
                <div className="font-mono text-2xl font-extrabold tabular-nums text-error-primary">{vulnCount}</div>
              </div>
            </div>

            <div className="hidden h-8 w-px bg-secondary sm:block" />

            {/* Reliability */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <Virus className="size-5 text-warning-primary" aria-hidden="true" />
              </span>
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-tertiary">Reliability</div>
                <div className="font-mono text-2xl font-extrabold tabular-nums text-warning-primary">{bugCount}</div>
              </div>
            </div>

            <div className="hidden h-8 w-px bg-secondary sm:block" />

            {/* Maintainability */}
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg border border-secondary bg-secondary/70 text-secondary">
                <Tool01 className="size-5 text-utility-blue-600 dark:text-utility-blue-400" aria-hidden="true" />
              </span>
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-tertiary">Maintainability</div>
                <div className="font-mono text-2xl font-extrabold tabular-nums text-primary">{codeSmellCount}</div>
              </div>
            </div>
          </div>

          {/* Lens Switcher */}
          <div role="group" aria-label="Issues code lens" className="flex items-center gap-1 rounded-lg border border-secondary bg-secondary p-1">
            <button
              type="button"
              aria-pressed={!newCode}
              onClick={() => patch('new_code', null)}
              className={cn(
                'rounded-md px-3.5 py-1.5 text-xs font-bold transition-all',
                !newCode
                  ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                  : 'text-tertiary hover:text-primary',
              )}
            >
              Overall Code
            </button>
            <button
              type="button"
              aria-pressed={newCode}
              onClick={() => patch('new_code', 'true')}
              className={cn(
                'rounded-md px-3.5 py-1.5 text-xs font-bold transition-all',
                newCode
                  ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                  : 'text-tertiary hover:text-primary',
              )}
            >
              New Code
            </button>
          </div>
        </div>
      )}

      {/* Main 2-Column Layout */}
      <div className="flex flex-col lg:flex-row gap-4 items-start">
        {/* Left Facet Sidebar (Sticky) */}
        <aside className="w-full lg:w-[270px] shrink-0 space-y-4 rounded-xl border border-secondary bg-primary p-4 shadow-xs lg:sticky lg:top-4 lg:self-start lg:max-h-[calc(100vh-2rem)] lg:overflow-y-auto">
          {/* Search Box */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-tertiary" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search title, rule, path..."
              className="w-full rounded-lg border border-secondary bg-primary py-2 pl-9 pr-8 text-xs text-primary shadow-xs placeholder:text-tertiary focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
            />
            {searchInput && (
              <button
                type="button"
                onClick={() => setSearchInput('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-tertiary hover:bg-secondary hover:text-primary"
                aria-label="Clear search"
              >
                <XClose className="size-3.5" />
              </button>
            )}
          </div>

          {/* Clear Filters CTA */}
          {hasActiveFilters && (
            <button
              type="button"
              onClick={clearAllFilters}
              className="flex w-full items-center justify-between rounded-lg border border-dashed border-secondary bg-secondary/30 px-2.5 py-1.5 text-xs font-semibold text-brand-secondary hover:bg-secondary/60 transition-colors"
            >
              <span>Reset active filters</span>
              <XClose className="size-3.5" />
            </button>
          )}

          {/* Software Quality Facets */}
          <div className="space-y-1.5 border-t border-secondary pt-3">
            <div className="text-[11px] font-bold uppercase tracking-wider text-tertiary px-1">
              Quality Domain
            </div>
            <FacetItem
              label="All Domains"
              active={!type}
              count={page?.summary?.total}
              onClick={() => patch('type', null)}
            />
            <FacetItem
              label="Security"
              icon={ShieldTick}
              active={type === 'vulnerability'}
              count={page?.facets?.types?.vulnerability}
              tone="text-error-primary"
              onClick={() => patch('type', type === 'vulnerability' ? null : 'vulnerability')}
            />
            <FacetItem
              label="Reliability (Bugs)"
              icon={Virus}
              active={type === 'bug'}
              count={page?.facets?.types?.bug}
              tone="text-warning-primary"
              onClick={() => patch('type', type === 'bug' ? null : 'bug')}
            />
            <FacetItem
              label="Maintainability"
              icon={Tool01}
              active={type === 'code_smell'}
              count={page?.facets?.types?.code_smell}
              tone="text-utility-blue-600 dark:text-utility-blue-400"
              onClick={() => patch('type', type === 'code_smell' ? null : 'code_smell')}
            />
          </div>

          {/* Severity Facets */}
          <div className="space-y-1.5 border-t border-secondary pt-3">
            <div className="text-[11px] font-bold uppercase tracking-wider text-tertiary px-1">
              Severity
            </div>
            <FacetItem
              label="All Severities"
              active={!severity}
              onClick={() => patch('severity', null)}
            />
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
              const count = page?.facets?.severities?.[sev]
              return (
                <FacetItem
                  key={sev}
                  label={sev}
                  active={severity === sev}
                  count={count}
                  pillStyle={severityBadge(sev)}
                  onClick={() => patch('severity', severity === sev ? null : sev)}
                />
              )
            })}
          </div>

          {/* Status Facets */}
          <div className="space-y-1.5 border-t border-secondary pt-3">
            <div className="text-[11px] font-bold uppercase tracking-wider text-tertiary px-1">
              Status
            </div>
            <FacetItem
              label="All Statuses"
              active={!status}
              onClick={() => patch('status', null)}
            />
            {ISSUE_STATUSES.map((st) => {
              const count = page?.facets?.statuses?.[st]
              return (
                <FacetItem
                  key={st}
                  label={issueStatusLabel(st)}
                  active={status === st}
                  count={count}
                  pillStyle={statusBadge(st)}
                  onClick={() => patch('status', status === st ? null : st)}
                />
              )
            })}
          </div>
        </aside>

        {/* Center: Issues Stream & Controls */}
        <div className="flex-1 min-w-0 space-y-3.5">
          {initialLoading && !page ? (
            <div className="flex items-center justify-center p-12 rounded-xl border border-secondary bg-primary">
              <Spinner className="size-6 text-brand" />
            </div>
          ) : error ? (
            <div className="space-y-3 p-5 rounded-xl border border-secondary bg-primary shadow-xs">
              <ErrorState message={error} />
              <Button variant="secondary" onClick={() => setRefresh((c) => c + 1)}>Retry</Button>
            </div>
          ) : !page || page.items.length === 0 ? (
            <div className="p-12 rounded-xl border border-secondary bg-primary shadow-xs">
              <EmptyState
                icon={Tool01}
                title="No issues match these filters"
                hint="Try resetting your filters or search keywords."
              />
            </div>
          ) : (
            <div className="space-y-3.5">
              {/* Stream Toolbar & View Mode Controls */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-secondary bg-primary px-4 py-2.5 shadow-xs text-xs">
                <div className="text-secondary">
                  Showing <span className="font-bold text-primary">{page.items.length}</span> issues
                  {viewMode === 'grouped' && filePaths.length > 0 && (
                    <span> across <span className="font-bold text-primary">{filePaths.length}</span> files</span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {/* Expand/Collapse All Buttons for Grouped Mode */}
                  {viewMode === 'grouped' && filePaths.length > 1 && (
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={expandAll}
                        className="inline-flex items-center gap-1 rounded-md border border-utility-blue-200 dark:border-utility-blue-800 bg-utility-blue-50 dark:bg-utility-blue-950/40 px-2.5 py-1 text-[11px] font-semibold text-utility-blue-700 dark:text-utility-blue-300 hover:bg-utility-blue-100 dark:hover:bg-utility-blue-900/50 shadow-2xs transition-all"
                      >
                        <ChevronDown className="size-3" aria-hidden="true" />
                        <span>Expand all</span>
                      </button>
                      <button
                        type="button"
                        onClick={collapseAll}
                        className="inline-flex items-center gap-1 rounded-md border border-secondary bg-secondary/70 px-2.5 py-1 text-[11px] font-semibold text-secondary hover:bg-secondary hover:text-primary shadow-2xs transition-all"
                      >
                        <ChevronUp className="size-3" aria-hidden="true" />
                        <span>Collapse all</span>
                      </button>
                    </div>
                  )}

                  {/* View Mode Toggle */}
                  <div className="flex items-center gap-1 rounded-lg border border-secondary bg-secondary p-0.5">
                    <button
                      type="button"
                      onClick={() => setViewMode('grouped')}
                      className={cn(
                        'rounded-md px-2.5 py-1 text-[11px] font-bold transition-all',
                        viewMode === 'grouped'
                          ? 'bg-primary text-brand-secondary shadow-2xs border border-secondary/60'
                          : 'text-tertiary hover:text-primary',
                      )}
                    >
                      Group by file
                    </button>
                    <button
                      type="button"
                      onClick={() => setViewMode('flat')}
                      className={cn(
                        'rounded-md px-2.5 py-1 text-[11px] font-bold transition-all',
                        viewMode === 'flat'
                          ? 'bg-primary text-brand-secondary shadow-2xs border border-secondary/60'
                          : 'text-tertiary hover:text-primary',
                      )}
                    >
                      Flat list
                    </button>
                  </div>
                </div>
              </div>

              {/* Grouped View Mode */}
              {viewMode === 'grouped' && (
                <div className="space-y-3">
                  {Object.entries(groupedIssues).map(([filePath, fileIssues]) => {
                    const isCollapsed = Boolean(collapsedFiles[filePath])
                    const isLimitExpanded = Boolean(expandedFileLimits[filePath])
                    const visibleIssues = isLimitExpanded
                      ? fileIssues
                      : fileIssues.slice(0, DEFAULT_FILE_LIMIT)
                    const remainingCount = fileIssues.length - DEFAULT_FILE_LIMIT

                    // Calculate sub-counts
                    const fileVulns = fileIssues.filter((i) => i.type === 'vulnerability').length
                    const fileBugs = fileIssues.filter((i) => i.type === 'bug').length
                    const fileSmells = fileIssues.filter((i) => i.type === 'code_smell').length

                    return (
                      <div
                        key={filePath}
                        className="rounded-xl border border-secondary bg-primary shadow-xs overflow-hidden transition-all"
                      >
                        {/* Interactive File Accordion Header */}
                        <div
                          onClick={() => toggleFileCollapse(filePath)}
                          className="flex items-center justify-between border-b border-secondary bg-secondary/35 px-4 py-2 text-xs cursor-pointer hover:bg-secondary/60 transition-colors select-none"
                        >
                          <div className="flex items-center gap-2 min-w-0 font-mono text-primary font-bold truncate">
                            {isCollapsed ? (
                              <ChevronRight className="size-4 text-tertiary shrink-0" aria-hidden="true" />
                            ) : (
                              <ChevronDown className="size-4 text-tertiary shrink-0" aria-hidden="true" />
                            )}
                            <File02 className="size-4 text-tertiary shrink-0" aria-hidden="true" />
                            <span className="truncate">{filePath}</span>
                            <span className="rounded-md border border-secondary bg-primary px-1.5 py-0.2 font-sans font-semibold text-[11px] text-tertiary shadow-2xs">
                              {fileIssues.length}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 shrink-0 text-[11px]" onClick={(e) => e.stopPropagation()}>
                            {/* Breakdown Pills */}
                            <div className="hidden sm:flex items-center gap-1.5 font-sans">
                              {fileVulns > 0 && (
                                <span className="inline-flex items-center gap-1 text-error-primary bg-error-primary/10 px-1.5 py-0.2 rounded font-semibold text-[10px]">
                                  <ShieldTick className="size-3" />
                                  <span>{fileVulns}</span>
                                </span>
                              )}
                              {fileBugs > 0 && (
                                <span className="inline-flex items-center gap-1 text-warning-primary bg-warning-primary/10 px-1.5 py-0.2 rounded font-semibold text-[10px]">
                                  <Virus className="size-3" />
                                  <span>{fileBugs}</span>
                                </span>
                              )}
                              {fileSmells > 0 && (
                                <span className="inline-flex items-center gap-1 text-utility-blue-600 dark:text-utility-blue-400 bg-utility-blue-50 dark:bg-utility-blue-950/40 px-1.5 py-0.2 rounded font-semibold text-[10px]">
                                  <Tool01 className="size-3" />
                                  <span>{fileSmells}</span>
                                </span>
                              )}
                            </div>

                            <Link
                              to={`/code-quality/projects/${encodeURIComponent(projectKey)}/code`}
                              className="inline-flex items-center gap-1 font-semibold text-brand-secondary hover:underline pl-1"
                            >
                              <span>Open</span>
                              <ArrowRight className="size-3" aria-hidden="true" />
                            </Link>
                          </div>
                        </div>

                        {/* Collapsible Issue List */}
                        {!isCollapsed && (
                          <div className="divide-y divide-secondary">
                            {visibleIssues.map((it) => (
                              <IssueItemRow
                                key={it.id}
                                issue={it}
                                isSelected={selectedId === it.id}
                                onClick={() => patch('id', selectedId === it.id ? null : it.id)}
                              />
                            ))}

                            {/* Progressive Disclosure (Show more in this file) */}
                            {remainingCount > 0 && (
                              <div className="bg-secondary/20 p-2.5 text-center">
                                <button
                                  type="button"
                                  onClick={() => toggleFileLimit(filePath)}
                                  className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-primary px-3 py-1 text-xs font-semibold text-brand-secondary hover:bg-secondary/60 shadow-2xs transition-all"
                                >
                                  {isLimitExpanded ? (
                                    <>
                                      <span>Show fewer (top {DEFAULT_FILE_LIMIT})</span>
                                      <ChevronUp className="size-3.5" />
                                    </>
                                  ) : (
                                    <>
                                      <span>Show all {fileIssues.length} issues in this file ({remainingCount} more)</span>
                                      <ChevronDown className="size-3.5" />
                                    </>
                                  )}
                                </button>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Flat View Mode */}
              {viewMode === 'flat' && (
                <div className="rounded-xl border border-secondary bg-primary shadow-xs overflow-hidden divide-y divide-secondary">
                  {page.items.map((it) => (
                    <IssueItemRow
                      key={it.id}
                      issue={it}
                      showFilePath
                      isSelected={selectedId === it.id}
                      onClick={() => patch('id', selectedId === it.id ? null : it.id)}
                    />
                  ))}
                </div>
              )}

              {/* Load More Button */}
              {page.next && (
                <div className="p-4 text-center">
                  <Button
                    variant="secondary"
                    loading={loading}
                    disabled={loading}
                    onClick={() => {
                      if (loading) return
                      setLoading(true)
                      api.listProjectIssues(projectKey, {
                        ...filter,
                        before_last_seen_at: page.next!.beforeLastSeenAt,
                        before_id: page.next!.beforeId,
                      })
                        .then((res) => setPage((prev) => (prev ? { ...res, items: [...prev.items, ...res.items] } : res)))
                        .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load more'))
                        .finally(() => setLoading(false))
                    }}
                  >
                    Load more issues
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Detail Inspector Drawer */}
        {selected && (
          <aside
            tabIndex={-1}
            role="region"
            aria-labelledby="issue-detail-title"
            className="w-full lg:w-[480px] xl:w-[520px] shrink-0 overflow-y-auto rounded-xl border border-secondary bg-primary p-5 shadow-xs transition-all lg:sticky lg:top-4 lg:self-start lg:max-h-[calc(100vh-2rem)]"
          >
            <IssueDetail
              projectKey={projectKey}
              issue={selected}
              onClose={() => patch('id', null)}
              onTransitioned={() => setRefresh((c) => c + 1)}
            />
          </aside>
        )}
      </div>
    </div>
  )
}

function IssueItemRow({
  issue,
  isSelected,
  showFilePath,
  onClick,
}: {
  issue: ProjectIssue
  isSelected: boolean
  showFilePath?: boolean
  onClick: () => void
}) {
  const meta = typeMeta(issue.type)
  const TypeIcon = meta.icon
  const line = extractLine(issue.location)

  return (
    <div
      onClick={onClick}
      className={cn(
        'group flex items-start justify-between gap-3 p-3.5 text-left transition-all cursor-pointer',
        isSelected
          ? 'bg-brand-primary/10 border-l-3 border-l-brand-solid shadow-2xs'
          : 'border-l-3 border-l-transparent hover:bg-secondary/40',
      )}
    >
      <div className="min-w-0 flex-1 space-y-1.5">
        {/* Title */}
        <div className="font-semibold text-xs text-primary leading-snug break-words group-hover:text-brand-secondary transition-colors">
          {cleanIssueTitle(issue.title || issue.ruleKey)}
        </div>

        {/* Badges & Meta Row */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {/* Domain & Severity pill */}
          <span className={cn('inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold border', meta.badge)}>
            <TypeIcon className="size-3 shrink-0" aria-hidden="true" />
            <span>{meta.label}</span>
            <span>·</span>
            <span className="font-mono font-bold uppercase">{issue.severity}</span>
          </span>

          {/* Status Badge */}
          <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold border capitalize', statusBadge(issue.status))}>
            {issueStatusLabel(issue.status)}
          </span>

          {/* File path if in flat mode */}
          {showFilePath && issue.file && (
            <span className="font-mono rounded border border-secondary bg-secondary/50 px-1.5 py-0.5 text-[11px] text-tertiary truncate max-w-[200px]">
              {issue.file}
            </span>
          )}

          {/* Line number */}
          {line && (
            <span className="font-mono rounded border border-secondary bg-secondary/50 px-1.5 py-0.5 text-[11px] text-secondary">
              L{line}
            </span>
          )}

          {/* Rule Key link */}
          <Link
            to={`/rules/${encodeURIComponent(issue.ruleKey)}`}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="inline-flex items-center gap-1 font-mono text-[11px] text-tertiary hover:text-brand-secondary hover:underline"
            title="View Rule Definition"
          >
            <span>{issue.ruleKey}</span>
            <LinkExternal02 className="size-2.5" aria-hidden="true" />
          </Link>

          {/* New Indicator */}
          {issue.isNew && (
            <span className="rounded bg-brand-primary/15 px-1 py-0.2 font-mono text-[10px] font-extrabold uppercase text-brand-secondary border border-brand/20">
              New
            </span>
          )}
        </div>
      </div>

      {/* Inspect action pill */}
      <div className="shrink-0 pt-0.5">
        <span className="inline-flex items-center gap-1 rounded-lg border border-secondary bg-primary px-2 py-1 text-[11px] font-semibold text-tertiary group-hover:border-brand/40 group-hover:text-primary shadow-2xs transition-all">
          <span>Inspect</span>
          <ArrowRight className="size-3" aria-hidden="true" />
        </span>
      </div>
    </div>
  )
}

function FacetItem({
  label,
  icon: Icon,
  active,
  count,
  tone,
  pillStyle,
  onClick,
}: {
  label: string
  icon?: any
  active: boolean
  count?: number
  tone?: string
  pillStyle?: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex w-full items-center justify-between rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all',
        active
          ? 'bg-brand-primary/10 text-brand-secondary border border-brand/30 shadow-2xs'
          : 'text-secondary hover:bg-secondary/60 hover:text-primary border border-transparent',
      )}
    >
      <span className="flex items-center gap-1.5 truncate">
        {Icon && <Icon className={cn('size-3.5 shrink-0', tone)} aria-hidden="true" />}
        <span className="truncate capitalize">{label}</span>
      </span>
      {typeof count === 'number' && (
        <span
          className={cn(
            'font-mono text-[11px] px-1.5 py-0.2 rounded-md font-bold',
            pillStyle || (active ? 'bg-brand/20 text-brand-secondary' : 'bg-secondary text-tertiary'),
          )}
        >
          {count}
        </span>
      )}
    </button>
  )
}

function IssueDetail({
  projectKey,
  issue,
  onClose,
  onTransitioned,
}: {
  projectKey: string
  issue: ProjectIssue
  onClose: () => void
  onTransitioned: () => void
}) {
  const [to, setTo] = useState<IssueStatus>(
    () => ISSUE_STATUSES.find((s) => canTransitionIssue(issue.status, s)) ?? issue.status,
  )
  const [rationale, setRationale] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const panelRef = useRef<HTMLDivElement>(null)

  const meta = typeMeta(issue.type)
  const TypeIcon = meta.icon

  const [showFullDesc, setShowFullDesc] = useState(false)
  const isLongDesc = (issue.description || '').length > 200 || (issue.description || '').split('\n').length > 4

  useEffect(() => {
    setShowFullDesc(false)
  }, [issue.id])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    panelRef.current?.focus()
  }, [issue.id])

  function copyLocation(text: string) {
    if (!text) return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  const targets = ISSUE_STATUSES.filter((s) => canTransitionIssue(issue.status, s))

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (rationale.trim().length < 3) {
      setErr('A rationale of at least 3 characters is required.')
      return
    }
    setBusy(true)
    setErr(null)
    api.transitionProjectIssue(projectKey, issue.id, to, rationale.trim(), issue.version)
      .then(() => {
        setRationale('')
        onTransitioned()
      })
      .catch((e) => setErr(e instanceof ApiError ? e.message : 'Transition failed'))
      .finally(() => setBusy(false))
  }

  return (
    <div ref={panelRef} tabIndex={-1} className="space-y-5 focus-visible:outline-none">
      {/* Header Bar */}
      <div className="flex items-start justify-between gap-3 border-b border-secondary pb-4">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold border', meta.badge)}>
              <TypeIcon className="size-3.5 shrink-0" />
              <span>{meta.label}</span>
            </span>
            <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 font-mono text-xs font-bold uppercase border', severityBadge(issue.severity))}>
              {issue.severity}
            </span>
            {issue.cwe && (
              <span className="font-mono rounded-md border border-secondary bg-secondary px-2 py-0.5 text-xs text-secondary">
                {issue.cwe}
              </span>
            )}
          </div>
          <h3 id="issue-detail-title" className="text-base font-bold text-primary leading-snug">
            {cleanIssueTitle(issue.title || issue.ruleKey)}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close inspector"
          className="rounded-lg p-1.5 text-tertiary hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 shrink-0"
        >
          <XClose className="size-4" aria-hidden="true" />
        </button>
      </div>

      {/* File & Line box */}
      <div>
        <div className="text-xs font-bold uppercase tracking-wider text-tertiary mb-1.5">
          Location
        </div>
        <div className="flex items-center justify-between gap-2 rounded-lg border border-secondary bg-secondary/30 p-2.5 shadow-2xs text-xs">
          <div className="flex items-center gap-1.5 min-w-0 font-mono text-primary truncate">
            <File02 className="size-3.5 text-tertiary shrink-0" aria-hidden="true" />
            <span className="truncate">{issue.location}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => copyLocation(issue.location)}
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium text-tertiary hover:bg-secondary hover:text-primary transition-colors"
              title={copied ? 'Copied location!' : 'Copy path'}
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
      </div>

      {/* Description / Explanation (Collapsible) */}
      <div>
        <div className="flex items-center justify-between text-xs font-bold uppercase tracking-wider text-tertiary mb-1.5">
          <span>Finding Description</span>
          {isLongDesc && (
            <button
              type="button"
              onClick={() => setShowFullDesc((v) => !v)}
              className="font-sans font-semibold text-brand-secondary hover:underline capitalize text-[11px]"
            >
              {showFullDesc ? 'Show less' : 'Show full'}
            </button>
          )}
        </div>
        <div className="rounded-xl border border-secondary bg-primary p-3.5 shadow-2xs relative">
          <div className={cn('relative font-mono text-xs leading-relaxed text-secondary transition-all', !showFullDesc && isLongDesc && 'max-h-[110px] overflow-hidden')}>
            <p className="whitespace-pre-wrap">
              {issue.description || 'No description was supplied for this rule.'}
            </p>
            {!showFullDesc && isLongDesc && (
              <div className="absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-primary to-transparent pointer-events-none" />
            )}
          </div>
          {isLongDesc && (
            <button
              type="button"
              onClick={() => setShowFullDesc((v) => !v)}
              className="mt-2.5 inline-flex items-center gap-1 text-[11px] font-semibold text-brand-secondary hover:underline"
            >
              <span>{showFullDesc ? 'Show less' : 'Show full description'}</span>
              {showFullDesc ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
            </button>
          )}
        </div>
      </div>

      {/* Triage Decision Form */}
      <form onSubmit={submit} className="rounded-xl border border-secondary bg-primary p-4 shadow-xs space-y-3.5">
        <div className="text-xs font-bold uppercase tracking-wider text-primary">
          Review Classification
        </div>
        <p className="text-xs text-tertiary">
          Current status: <span className="font-semibold text-primary capitalize">{issueStatusLabel(issue.status)}</span>
        </p>

        {targets.length === 0 ? (
          <p className="text-xs text-tertiary">No transitions available from this status.</p>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="text-xs font-medium text-secondary mb-1.5 block">
                Target Status
              </label>
              <div className="grid grid-cols-2 gap-2">
                {targets.map((st) => (
                  <button
                    key={st}
                    type="button"
                    disabled={busy}
                    onClick={() => setTo(st)}
                    className={cn(
                      'flex items-center justify-between rounded-lg border p-2 text-xs font-semibold transition-all',
                      to === st
                        ? 'border-brand-solid bg-brand-primary/10 text-brand-secondary ring-1 ring-brand-solid'
                        : 'border-secondary bg-secondary/40 text-secondary hover:bg-secondary hover:text-primary',
                    )}
                  >
                    <span>{issueStatusLabel(st)}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="issue-transition-rationale" className="text-xs font-medium text-secondary mb-1.5 block">
                Rationale <span className="text-error-primary">*</span>
              </label>
              <textarea
                id="issue-transition-rationale"
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                rows={3}
                disabled={busy}
                className="w-full rounded-lg border border-secondary bg-primary px-3 py-2 text-xs text-primary shadow-2xs focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/60"
                placeholder="Enter triage notes or rationale for this status change..."
              />
            </div>

            {err && <p className="text-xs font-medium text-error-primary">{err}</p>}

            <Button
              type="submit"
              variant="brand"
              loading={busy}
              disabled={busy}
              className="w-full !bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs font-semibold"
            >
              Apply Classification
            </Button>
          </div>
        )}
      </form>
    </div>
  )
}
