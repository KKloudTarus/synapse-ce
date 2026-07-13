import { Search, ChevronRight, X, AlertCircle, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../lib/api'
import { hasActiveRuleFilters, parseRuleFilters, serializeRuleFilters } from '../lib/ruleFilters'
import { deriveRuleFacets, formatRuleSeverity, formatRuleType } from '../lib/ruleFormat'
import type { RuleFacets, RuleSummary, RuleType, RuleSeverity } from '../lib/types'
import { Card, EmptyState, Spinner, cn } from '../components/ui'
import { FacetFilter } from '../components/rules/FacetFilter'
import { VirtualTable } from '../components/VirtualTable'
import { VirtualRuleCards } from '../components/rules/VirtualRuleCards'

type FilterKey = 'languages' | 'types' | 'severities' | 'tags' | 'cwe'

function formatFilterChip(key: FilterKey, val: string): string {
  if (key === 'types') return formatRuleType(val as RuleType)
  if (key === 'severities') return formatRuleSeverity(val as RuleSeverity)
  return val
}

export default function Rules() {
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => parseRuleFilters(params), [params])
  const activeFilters = hasActiveRuleFilters(filters)

  const [catalogRules, setCatalogRules] = useState<RuleSummary[]>([])
  const [catalogLoading, setCatalogLoading] = useState(true)
  const [catalogError, setCatalogError] = useState<string | null>(null)
  const [facets, setFacets] = useState<RuleFacets>({ languages: [], types: [], severities: [], tags: [], cwe: [] })

  const [resultRules, setResultRules] = useState<RuleSummary[]>([])
  const [resultLoading, setResultLoading] = useState(false)
  const [resultError, setResultError] = useState<string | null>(null)

  const [filteredRetryVersion, setFilteredRetryVersion] = useState(0)
  const reqSeq = useRef(0)
  const searchInputRef = useRef<HTMLInputElement>(null)

  const [query, setQuery] = useState(filters.query)

  useEffect(() => {
    setQuery(filters.query)
  }, [filters.query])

  useEffect(() => {
    const timeout = setTimeout(() => {
      if (query !== filters.query) {
        const nextFilters = { ...filters, query }
        setParams(serializeRuleFilters(nextFilters), { replace: true })
      }
    }, 250)
    return () => clearTimeout(timeout)
  }, [query, filters, setParams])

  const loadCatalog = useCallback(() => {
    let active = true
    setCatalogLoading(true)
    setCatalogError(null)

    api.listRules()
      .then((res) => {
        if (!active) return
        setCatalogRules(res)
        setFacets(deriveRuleFacets(res))
      })
      .catch((err) => {
        if (!active) return
        setCatalogError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        if (active) setCatalogLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    const cleanup = loadCatalog()
    return cleanup
  }, [loadCatalog])

  // Sync catalogRules → resultRules when no filters are active.
  useEffect(() => {
    if (!activeFilters) {
      setResultRules(catalogRules)
      setResultError(null)
      setResultLoading(false)
    }
  }, [activeFilters, catalogRules])

  // Filtered request — does NOT depend on catalogRules.
  const canonicalFilterKey = params.toString()
  useEffect(() => {
    if (!activeFilters) return

    let active = true
    const seq = ++reqSeq.current
    setResultError(null)
    setResultLoading(true)

    api.listRules(filters)
      .then((res) => {
        if (!active || seq !== reqSeq.current) return
        setResultRules(res)
      })
      .catch((err) => {
        if (!active || seq !== reqSeq.current) return
        setResultError(err instanceof ApiError ? err.message : 'An error occurred')
      })
      .finally(() => {
        if (active && seq === reqSeq.current) setResultLoading(false)
      })

    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeFilters, canonicalFilterKey, filteredRetryVersion])

  const handleFilterChange = (key: FilterKey, value: string[]) => {
    const nextFilters = { ...filters, [key]: value }
    setParams(serializeRuleFilters(nextFilters))
  }

  const removeChip = (key: FilterKey, val: string) => {
    const nextFilters = { ...filters, [key]: filters[key].filter(v => v !== val) }
    setParams(serializeRuleFilters(nextFilters))
  }

  const clearQuery = () => {
    setQuery('')
    const nextFilters = { ...filters, query: '' }
    setParams(serializeRuleFilters(nextFilters))
    searchInputRef.current?.focus()
  }

  const clearAllFilters = () => {
    setQuery('')
    setParams(new URLSearchParams())
  }

  const handleSearchKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      clearQuery()
    }
  }

  return (
    <div className="mx-auto max-w-6xl animate-fade-in pb-12">
      <header className="bg-hero mb-6 flex flex-col gap-4 rounded-xl border border-border p-6 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Rules</h1>
          <p className="mt-1.5 max-w-xl text-sm text-mutedfg">
            Browse first-party security and code-quality rules, their rationale, and remediation guidance.
          </p>
        </div>
        <div className="flex shrink-0 items-center justify-end md:self-end">
          {!catalogLoading && !catalogError && (
            <p className="text-sm font-medium text-mutedfg" aria-live="polite">
              {activeFilters ? `${resultRules.length} of ${catalogRules.length} rules` : `${catalogRules.length} rules`}
            </p>
          )}
        </div>
      </header>

      {catalogError ? (
        <div className="mb-6 rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-600 dark:text-red-400">
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="size-4" />
            Failed to load catalog
          </div>
          <p className="mt-1 ml-6">{catalogError}</p>
          <button
            onClick={() => loadCatalog()}
            className="mt-3 ml-6 inline-flex items-center gap-1.5 text-xs font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface rounded-sm"
          >
            <RefreshCw className="size-3" />
            Retry
          </button>
        </div>
      ) : catalogLoading ? (
        <Spinner className="mt-12 size-6 text-brand" />
      ) : (
        <>
          <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center">
            <div className="relative max-w-md flex-1">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-mutedfg" />
              <input
                ref={searchInputRef}
                aria-label="Search rules"
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleSearchKey}
                placeholder="Search rules..."
                className="w-full rounded-lg border border-border bg-card py-2 pl-9 pr-8 text-sm text-foreground transition-colors placeholder:text-mutedfg focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand shadow-sm"
                maxLength={256}
              />
              {query && (
                <button
                  type="button"
                  onClick={clearQuery}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-mutedfg transition-colors hover:bg-surface hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                >
                  <X className="size-3.5" />
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <FacetFilter
                label="Language"
                values={facets.languages}
                selected={filters.languages}
                onChange={(v) => handleFilterChange('languages', v)}
              />
              <FacetFilter
                label="Type"
                values={facets.types}
                selected={filters.types}
                formatValue={formatRuleType}
                onChange={(v) => handleFilterChange('types', v)}
              />
              <FacetFilter
                label="Severity"
                values={facets.severities}
                selected={filters.severities}
                formatValue={formatRuleSeverity}
                onChange={(v) => handleFilterChange('severities', v)}
              />
              <FacetFilter
                label="Tag"
                values={facets.tags}
                selected={filters.tags}
                onChange={(v) => handleFilterChange('tags', v)}
              />
              <FacetFilter
                label="CWE"
                values={facets.cwe}
                selected={filters.cwe}
                onChange={(v) => handleFilterChange('cwe', v)}
              />
              {activeFilters && (
                <button
                  type="button"
                  onClick={clearAllFilters}
                  className="ml-2 text-sm font-medium text-branddim transition-colors hover:text-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface rounded-sm"
                >
                  Clear all
                </button>
              )}
            </div>
          </div>

          {activeFilters && (
            <div className="mb-6 flex flex-wrap gap-2">
              {(['languages', 'types', 'severities', 'tags', 'cwe'] as const).map(key => 
                filters[key].map(val => (
                  <div key={`${key}-${val}`} className="flex items-center gap-1 rounded-md bg-brand/10 pl-2.5 pr-1 py-1 text-xs font-medium text-branddim">
                    {formatFilterChip(key, val)}
                    <button
                      type="button"
                      aria-label={`Remove ${formatFilterChip(key, val)} filter`}
                      onClick={() => removeChip(key, val)}
                      className="rounded-full p-0.5 transition-colors hover:bg-brand/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                    >
                      <X className="size-3" />
                    </button>
                  </div>
                ))
              )}
            </div>
          )}

          <div className="space-y-4" aria-busy={resultLoading}>
            {resultError && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-600 dark:text-red-400">
                <div className="flex items-center gap-2 font-medium">
                  <AlertCircle className="size-4" />
                  Failed to load filtered results
                </div>
                <p className="mt-1 ml-6">{resultError}</p>
                <button
                  type="button"
                  onClick={() => setFilteredRetryVersion((v) => v + 1)}
                  className="mt-3 ml-6 inline-flex items-center gap-1.5 text-xs font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface rounded-sm"
                >
                  <RefreshCw className="size-3" />
                  Retry
                </button>
              </div>
            )}

            {!activeFilters && catalogRules.length === 0 ? (
              <EmptyState
                icon={Search}
                title="No rules are available."
                hint="The catalog is currently empty."
              />
            ) : activeFilters && resultRules.length === 0 && !resultLoading && !resultError ? (
              <EmptyState
                icon={Search}
                title="No rules match these filters."
                hint="Try adjusting or removing some filters to find what you're looking for."
                action={
                  <button
                    type="button"
                    onClick={clearAllFilters}
                    className="mt-4 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-brandfg hover:bg-brand/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-surface"
                  >
                    Clear all filters
                  </button>
                }
              />
            ) : (
              <div className={cn("transition-opacity duration-200", resultLoading && "opacity-50 pointer-events-none")}>
                {/* Desktop Table */}
                <div className="hidden md:block">
                  <Card bodyClass="p-0">
                    <VirtualTable
                      columns={[
                        {
                          header: 'Rule',
                          className: 'min-w-[22rem] flex-1',
                          cell: (rule) => (
                            <div className="flex flex-col gap-1 py-3">
                              <Link 
                                to={`/rules/${encodeURIComponent(rule.key)}`}
                                state={{ from: params.toString() ? `?${params.toString()}` : '' }}
                                className="font-semibold text-foreground hover:text-brand focus-visible:outline-none focus-visible:underline"
                              >
                                {rule.name}
                              </Link>
                              <div className="flex items-center gap-2">
                                <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-mutedfg border border-border/50">{rule.key}</span>
                              </div>
                              <p className="text-xs text-mutedfg line-clamp-2 mt-0.5" title={rule.description}>{rule.description}</p>
                            </div>
                          ),
                        },
                        {
                          header: 'Language',
                          className: 'w-28 shrink-0',
                          cell: (rule) => <span className="capitalize text-mutedfg">{rule.language}</span>,
                        },
                        {
                          header: 'Type',
                          className: 'w-36 shrink-0',
                          cell: (rule) => <span className="text-mutedfg">{formatRuleType(rule.type)}</span>,
                        },
                        {
                          header: 'Qualities',
                          className: 'w-44 shrink-0',
                          cell: (rule) => (
                            <div className="flex flex-col gap-1 text-mutedfg">
                              {rule.qualities.length > 0 ? rule.qualities.map(q => <span key={q} className="capitalize">{q}</span>) : '-'}
                            </div>
                          ),
                        },
                        {
                          header: 'Severity',
                          className: 'w-28 shrink-0',
                          cell: (rule) => <span className="text-mutedfg">{formatRuleSeverity(rule.defaultSeverity)}</span>,
                        },
                        {
                          header: 'Tags',
                          className: 'w-56 shrink-0',
                          cell: (rule) => {
                            const maxTags = 3
                            const visibleTags = rule.tags.slice(0, maxTags)
                            const extraTags = rule.tags.length - maxTags
                            return (
                              <div className="flex flex-wrap gap-1 text-mutedfg">
                                {visibleTags.map(t => (
                                  <span key={t} className="rounded bg-surface px-1.5 py-0.5 text-[11px] border border-border/50">{t}</span>
                                ))}
                                {extraTags > 0 && (
                                  <span className="rounded bg-surface px-1.5 py-0.5 text-[11px] border border-border/50">+{extraTags}</span>
                                )}
                              </div>
                            )
                          },
                        },
                        {
                          header: '',
                          className: 'w-10 shrink-0 text-right',
                          cell: (rule) => (
                            <Link 
                              to={`/rules/${encodeURIComponent(rule.key)}`}
                              state={{ from: params.toString() ? `?${params.toString()}` : '' }}
                              aria-label={`View ${rule.name} details`}
                              className="inline-flex size-8 items-center justify-center rounded-lg text-mutedfg hover:bg-elevated hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                            >
                              <ChevronRight className="size-4" />
                            </Link>
                          ),
                        },
                      ]}
                      items={resultRules}
                      rowKey={(rule) => rule.key}
                      rowHeight={96}
                      maxHeightClass="max-h-[70vh]"
                      tableMinWidthClass="min-w-[72rem]"
                      totalItems={resultRules.length}
                    />
                  </Card>
                </div>

                {/* Mobile Cards */}
                <VirtualRuleCards 
                  rules={resultRules} 
                  detailFrom={params.toString() ? `?${params.toString()}` : ''} 
                />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
