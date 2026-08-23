import { Fragment, useState } from 'react'
import { AlertCircle, ChevronDown, RefreshCw01, SearchLg } from '@untitledui/icons'
import { Card, EmptyState, Spinner, cn } from '../../components/ui'
import { VirtualRuleCards } from '../../components/rules/VirtualRuleCards'
import { formatRuleSeverity, formatRuleType } from '../../lib/ruleFormat'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import { RuleFilterBar } from './RuleFilterBar'
import { useRulesSearch } from './useRulesSearch'

// Cache rule details so re-expanding is instant (no refetch)
const ruleDetailCache = new Map<string, any>()

function RuleInlineDetail({ ruleKey }: { ruleKey: string }) {
  const cached = ruleDetailCache.get(ruleKey)
  const { data, error, loading } = useFetch(
    () => cached ? Promise.resolve(cached) : api.getRule(ruleKey).then(d => { ruleDetailCache.set(ruleKey, d); return d }),
    { deps: [ruleKey] }
  )
  const resolved = data || cached
  if (loading && !resolved) {
    return (
      <div className="flex h-8 items-center gap-2 text-xs text-tertiary">
        <Spinner className="size-3" />
        <span>Loading…</span>
      </div>
    )
  }
  if (error && !resolved) return <p className="text-sm text-critical">{error}</p>
  if (!resolved) return null

  const compliant = resolved.compliantExample || (resolved as any).examples?.compliant
  const noncompliant = resolved.noncompliantExample || (resolved as any).examples?.nonCompliant || (resolved as any).examples?.noncompliant

  return (
    <div className="space-y-3 text-sm">
      {resolved.description && (
        <div>
          <h3 className="font-semibold text-primary">Description</h3>
          <p className="mt-1 text-tertiary">{resolved.description}</p>
        </div>
      )}
      {resolved.rationale && (
        <div>
          <h3 className="font-semibold text-primary">Rationale</h3>
          <p className="mt-1 text-tertiary">{resolved.rationale}</p>
        </div>
      )}
      {(compliant || noncompliant) && (
        <div className="grid gap-3 sm:grid-cols-2">
          {compliant && (
            <div className="flex flex-col overflow-hidden rounded-lg border border-utility-success-200 bg-primary dark:border-utility-success-800">
              <div className="flex items-center gap-1.5 border-b border-utility-success-200 bg-utility-success-50 px-3 py-1.5 text-xs font-semibold text-utility-success-700 dark:border-utility-success-800 dark:bg-utility-success-950/40 dark:text-utility-success-300">
                ✓ Compliant
              </div>
              <pre className="overflow-x-auto p-3 text-xs font-mono text-primary"><code>{compliant}</code></pre>
            </div>
          )}
          {noncompliant && (
            <div className="flex flex-col overflow-hidden rounded-lg border border-utility-red-200 bg-primary dark:border-utility-red-800">
              <div className="flex items-center gap-1.5 border-b border-utility-red-200 bg-utility-red-50 px-3 py-1.5 text-xs font-semibold text-utility-red-700 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-300">
                ✗ Non-compliant
              </div>
              <pre className="overflow-x-auto p-3 text-xs font-mono text-primary"><code>{noncompliant}</code></pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Rules() {
  const [expandedKey, setExpandedKey] = useState<string | null>(null)
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
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Rules</h1>
          <p className="mt-1 text-sm text-secondary">
            Security and code-quality rules with rationale and examples
          </p>
        </div>
        <div className="flex shrink-0 items-center justify-end">
          {!catalogLoading && !catalogError && (
            <div
              className="inline-flex items-center rounded-full border border-brand/30 bg-brand-primary/10 px-3.5 py-1.5 text-base font-bold text-brand-secondary shadow-xs tabular-nums"
              aria-live="polite"
            >
              {activeFilters ? `${resultRules.length} of ${catalogRules.length} rules` : `${catalogRules.length} rules`}
            </div>
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
            className="mt-3 ml-6 inline-flex items-center gap-1.5 text-xs font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand rounded-sm"
          >
            <RefreshCw01 className="size-3" />
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
                  className="mt-3 ml-6 inline-flex items-center gap-1.5 text-xs font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand rounded-sm"
                >
                  <RefreshCw01 className="size-3" />
                  Retry
                </button>
              </div>
            )}

            {!activeFilters && catalogRules.length === 0 ? (
              <EmptyState
                icon={SearchLg}
                title="No rules are available."
                hint="The catalog is currently empty."
              />
            ) : activeFilters && resultRules.length === 0 && !resultLoading && !resultError ? (
              <EmptyState
                icon={SearchLg}
                title="No rules match these filters."
                hint="Try adjusting or removing some filters to find what you're looking for."
                action={
                  <button
                    type="button"
                    onClick={clearAllFilters}
                    className="mt-4 rounded-lg bg-brand px-4 py-2 text-sm font-semibold text-white hover:bg-brand/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                  >
                    Clear all filters
                  </button>
                }
              />
            ) : (
              <div className={cn("transition-opacity duration-200", resultLoading && "opacity-50 pointer-events-none")}>
                {/* Desktop Table */}
                <div className="hidden md:block">
                  <Card bodyClass="p-0 overflow-hidden">
                    <div className="overflow-x-auto">
                      <table role="table" aria-rowcount={resultRules.length + 1} className="min-w-full text-left text-sm whitespace-nowrap">
                        <thead className="bg-secondary/95 text-[11px] uppercase tracking-[0.14em] text-primary border-b border-secondary sticky top-0">
                          <tr role="row">
                            <th scope="col" className="px-5 py-3 font-semibold min-w-[20rem]">Rule</th>
                            <th scope="col" className="px-4 py-3 font-semibold w-28">Language</th>
                            <th scope="col" className="px-4 py-3 font-semibold w-32">Type</th>
                            <th scope="col" className="px-4 py-3 font-semibold w-36">Qualities</th>
                            <th scope="col" className="px-4 py-3 font-semibold w-28">Severity</th>
                            <th scope="col" className="px-4 py-3 font-semibold w-48">Tags</th>
                            <th scope="col" className="px-4 py-3 font-semibold w-10 text-right"><span className="sr-only">Expand</span></th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-secondary">
                          {resultRules.map((rule) => {
                            const isExpanded = expandedKey === rule.key
                            const maxTags = 3
                            const visibleTags = rule.tags.slice(0, maxTags)
                            const extraTags = rule.tags.length - maxTags
                            return (
                              <Fragment key={rule.key}>
                                <tr
                                  role="row"
                                  className={cn(
                                    'cursor-pointer transition-colors hover:bg-secondary/30',
                                    isExpanded && 'bg-brand-primary/10 border-l-2 border-brand-solid'
                                  )}
                                  onClick={() => setExpandedKey(isExpanded ? null : rule.key)}
                                >
                                  <td className="px-5 py-3">
                                    <div className="flex items-center gap-2">
                                      <span className={cn("font-semibold", isExpanded ? "text-brand-secondary" : "text-primary")}>
                                        {rule.name}
                                      </span>
                                      <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-tertiary border border-secondary">
                                        {rule.key}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-3 capitalize text-secondary font-medium">
                                    {rule.language}
                                  </td>
                                  <td className="px-4 py-3 text-tertiary">
                                    {formatRuleType(rule.type)}
                                  </td>
                                  <td className="px-4 py-3 text-tertiary">
                                    {rule.qualities.length > 0 ? rule.qualities.join(', ') : '-'}
                                  </td>
                                  <td className="px-4 py-3 text-tertiary">
                                    {formatRuleSeverity(rule.defaultSeverity)}
                                  </td>
                                  <td className="px-4 py-3 text-tertiary">
                                    <div className="flex flex-wrap gap-1">
                                      {visibleTags.map((t) => (
                                        <span key={t} className="rounded bg-secondary px-1.5 py-0.5 text-[11px] border border-secondary">
                                          {t}
                                        </span>
                                      ))}
                                      {extraTags > 0 && (
                                        <span className="rounded bg-secondary px-1.5 py-0.5 text-[11px] border border-secondary">
                                          +{extraTags}
                                        </span>
                                      )}
                                    </div>
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    <ChevronDown
                                      className={cn(
                                        'size-4 text-quaternary transition-transform duration-200 inline-block',
                                        isExpanded && 'rotate-180 text-brand-secondary'
                                      )}
                                      aria-hidden="true"
                                    />
                                  </td>
                                </tr>
                                {isExpanded && (
                                  <tr role="row">
                                    <td colSpan={7} className="border-t border-brand/20 bg-secondary/15 px-5 py-4 whitespace-normal">
                                      <RuleInlineDetail ruleKey={rule.key} />
                                    </td>
                                  </tr>
                                )}
                              </Fragment>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
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
