import { ChevronRight, Search, AlertCircle, RefreshCw } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Card, EmptyState, Spinner, cn } from '../../components/ui'
import { VirtualTable } from '../../components/synapse/VirtualTable'
import { VirtualRuleCards } from '../../components/rules/VirtualRuleCards'
import { formatRuleSeverity, formatRuleType } from '../../lib/ruleFormat'
import { RuleFilterBar } from './RuleFilterBar'
import { useRulesSearch } from './useRulesSearch'

export default function Rules() {
  const {
    params,
    filters,
    activeFilters,
    catalogRules,
    catalogLoading,
    catalogError,
    facets,
    resultRules,
    resultLoading,
    resultError,
    query,
    setQuery,
    searchInputRef,
    loadCatalog,
    handleFilterChange,
    removeChip,
    clearQuery,
    clearAllFilters,
    retryFiltered,
  } = useRulesSearch()

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
          <RuleFilterBar
            facets={facets}
            filters={filters}
            activeFilters={activeFilters}
            query={query}
            searchInputRef={searchInputRef}
            onQueryChange={setQuery}
            onFilterChange={handleFilterChange}
            onRemoveChip={removeChip}
            onClearQuery={clearQuery}
            onClearAll={clearAllFilters}
            onSearchKey={handleSearchKey}
          />

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
                  onClick={retryFiltered}
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
