import {
  ArrowRight,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  File02,
  SearchLg as Search,
  ShieldTick,
  Tool01,
  Virus,
  XClose,
} from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Button, EmptyState, ErrorState, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
import {
  ISSUE_STATUSES,
  issueStatusLabel,
  type IssueListFilter,
  type IssuePage,
  type IssueStatus,
  type RuleType,
  type Severity,
} from '../../lib/types'
import { useProjectRouteContext } from './CodeQualityProject'
import { FacetItem, IssueItemRow } from './components/IssueItemRow'
import { IssueDetail } from './components/IssueDetail'
import { DEFAULT_FILE_LIMIT, groupIssuesByFile, severityBadge, statusBadge } from './components/projectIssueHelpers'

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
