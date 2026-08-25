import { Fragment, useEffect, useMemo, useState } from 'react'
import {
  AlertCircle,
  ArrowUpRight,
  Check,
  CheckCircle,
  ChevronDown,
  Copy01,
  RefreshCw01,
  SearchLg,
  XCircle,
} from '@untitledui/icons'
import { Link } from 'react-router-dom'
import { Button, Card, EmptyState, Spinner, cn } from '../../components/ui'
import { SeverityBadge } from '../../components/synapse/SeverityBadge'
import { VirtualRuleCards } from '../../components/rules/VirtualRuleCards'
import { formatRuleType } from '../../lib/ruleFormat'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import { RuleFilterBar } from './RuleFilterBar'
import { useRulesSearch } from './useRulesSearch'

// Cache rule details so re-expanding is instant (no refetch)
const ruleDetailCache = new Map<string, any>()

function CopyButton({ text, ariaLabel = 'Copy' }: { text: string; ariaLabel?: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation()
    void navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={copied ? 'Copied' : ariaLabel}
      title={copied ? 'Copied to clipboard!' : ariaLabel}
      className="rounded p-1 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
    >
      {copied ? <Check className="size-3.5 text-utility-success-600 dark:text-utility-success-400" /> : <Copy01 className="size-3.5" />}
    </button>
  )
}

function RuleTypeBadge({ type }: { type: string }) {
  const label = formatRuleType(type as any)
  let colorClass = 'bg-secondary text-secondary ring-border-secondary'
  if (type === 'vulnerability' || type === 'bug') {
    colorClass = 'bg-utility-error-50 text-utility-error-700 ring-utility-error-200 dark:bg-utility-error-950/40 dark:text-utility-error-300 dark:ring-utility-error-800'
  } else if (type === 'security_hotspot') {
    colorClass = 'bg-utility-warning-50 text-utility-warning-700 ring-utility-warning-200 dark:bg-utility-warning-950/40 dark:text-utility-warning-300 dark:ring-utility-warning-800'
  } else if (type === 'code_smell') {
    colorClass = 'bg-utility-blue-50 text-utility-blue-700 ring-utility-blue-200 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 dark:ring-utility-blue-800'
  }
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset', colorClass)}>
      {label}
    </span>
  )
}

function FormattedRationale({ text }: { text: string }) {
  const urlRegex = /(https?:\/\/[^\s]+)/g
  const parts = text.split(urlRegex)
  return (
    <p className="mt-1 text-secondary leading-relaxed">
      {parts.map((part, i) =>
        urlRegex.test(part) ? (
          <a
            key={i}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 text-brand-secondary font-medium underline underline-offset-2 hover:text-brand"
            onClick={(e) => e.stopPropagation()}
          >
            {part}
            <ArrowUpRight className="size-3" />
          </a>
        ) : (
          part
        )
      )}
    </p>
  )
}

function RuleInlineDetail({ ruleKey, initialDescription }: { ruleKey: string; initialDescription?: string }) {
  const cached = ruleDetailCache.get(ruleKey)
  const { data, error, loading } = useFetch(
    () => cached ? Promise.resolve(cached) : api.getRule(ruleKey).then(d => { ruleDetailCache.set(ruleKey, d); return d }),
    { deps: [ruleKey] }
  )
  const resolved = data || cached
  const description = resolved?.description || initialDescription

  const compliant = resolved?.compliantExample || (resolved as any)?.examples?.compliant
  const noncompliant = resolved?.noncompliantExample || (resolved as any)?.examples?.nonCompliant || (resolved as any)?.examples?.noncompliant

  return (
    <div className="space-y-4 text-sm">
      {description && (
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-secondary">Description</h3>
          <p className="mt-1 text-secondary leading-relaxed">{description}</p>
        </div>
      )}
      {loading && !resolved && (
        <div className="flex h-7 items-center gap-2 text-xs text-tertiary">
          <Spinner className="size-3 text-brand" />
          <span>Loading rationale &amp; examples…</span>
        </div>
      )}
      {error && !resolved && <p className="text-sm text-critical">{error}</p>}
      {resolved && (
        <>
          {resolved.rationale && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-secondary">Rationale</h3>
              <FormattedRationale text={resolved.rationale} />
            </div>
          )}
          {(compliant || noncompliant) && (
            <div className="grid gap-4 sm:grid-cols-2 pt-1">
              {compliant && (
                <div className="flex flex-col overflow-hidden rounded-lg border border-utility-blue-200 bg-primary dark:border-utility-blue-800 shadow-xs">
                  <div className="flex items-center justify-between border-b border-utility-blue-200 bg-utility-blue-50 px-3 py-1.5 text-xs font-semibold text-utility-blue-700 dark:border-utility-blue-800 dark:bg-utility-blue-950/40 dark:text-utility-blue-300">
                    <span className="inline-flex items-center gap-1.5">
                      <CheckCircle className="size-3.5" aria-hidden="true" /> Compliant
                    </span>
                    <CopyButton text={compliant} ariaLabel="Copy compliant code" />
                  </div>
                  <pre className="overflow-x-auto p-3 text-xs font-mono text-primary leading-normal"><code>{compliant}</code></pre>
                </div>
              )}
              {noncompliant && (
                <div className="flex flex-col overflow-hidden rounded-lg border border-utility-red-200 bg-primary dark:border-utility-red-800 shadow-xs">
                  <div className="flex items-center justify-between border-b border-utility-red-200 bg-utility-red-50 px-3 py-1.5 text-xs font-semibold text-utility-red-700 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-300">
                    <span className="inline-flex items-center gap-1.5">
                      <XCircle className="size-3.5" aria-hidden="true" /> Non-compliant
                    </span>
                    <CopyButton text={noncompliant} ariaLabel="Copy non-compliant code" />
                  </div>
                  <pre className="overflow-x-auto p-3 text-xs font-mono text-primary leading-normal"><code>{noncompliant}</code></pre>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function Rules() {
  const [expandedKey, setExpandedKey] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

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

  useEffect(() => {
    setPage(1)
  }, [query, filters])

  const handleSearchKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      clearQuery()
    }
  }

  const detailFrom = params.toString() ? `?${params.toString()}` : ''

  const totalPages = Math.max(1, Math.ceil(resultRules.length / pageSize))
  const paginatedRules = useMemo(() => {
    const start = (page - 1) * pageSize
    return resultRules.slice(start, start + pageSize)
  }, [resultRules, page, pageSize])

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
                    <table role="table" aria-rowcount={resultRules.length + 1} className="w-full table-fixed text-left text-sm">
                      <thead className="bg-secondary/95 text-[11px] uppercase tracking-[0.14em] text-primary border-b border-secondary sticky top-0">
                        <tr role="row">
                          <th scope="col" className="px-5 py-3 font-semibold w-[36%]">Rule &amp; Key</th>
                          <th scope="col" className="px-4 py-3 font-semibold w-[13%]">Language</th>
                          <th scope="col" className="px-4 py-3 font-semibold w-[13%]">Type</th>
                          <th scope="col" className="px-4 py-3 font-semibold w-[11%]">Severity</th>
                          <th scope="col" className="px-4 py-3 font-semibold w-[23%]">Tags</th>
                          <th scope="col" className="px-4 py-3 font-semibold w-[4%] text-right"><span className="sr-only">Actions</span></th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-secondary">
                        {paginatedRules.map((rule) => {
                          const isExpanded = expandedKey === rule.key
                          const maxTags = 2
                          const visibleTags = (rule.tags ?? []).slice(0, maxTags)
                          const extraTags = (rule.tags ?? []).length - maxTags

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
                                <td className="px-5 py-3 overflow-hidden">
                                  <div className="flex flex-col gap-1 min-w-0">
                                    <span className={cn("font-semibold truncate leading-snug", isExpanded ? "text-brand-secondary" : "text-primary")}>
                                      {rule.name}
                                    </span>
                                    <div className="flex items-center gap-1.5">
                                      <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-tertiary border border-secondary shrink-0 truncate max-w-[220px]">
                                        {rule.key}
                                      </span>
                                      <CopyButton text={rule.key} ariaLabel={`Copy ${rule.key}`} />
                                    </div>
                                  </div>
                                </td>
                                <td className="px-4 py-3 capitalize text-secondary font-medium">
                                  {rule.language}
                                </td>
                                <td className="px-4 py-3">
                                  <RuleTypeBadge type={rule.type} />
                                </td>
                                <td className="px-4 py-3">
                                  <SeverityBadge severity={rule.defaultSeverity as any} size="sm" />
                                </td>
                                <td className="px-4 py-3 text-tertiary overflow-hidden">
                                  <div className="flex items-center gap-1.5 flex-nowrap overflow-hidden">
                                    {visibleTags.map((t) => (
                                      <span
                                        key={t}
                                        className="inline-flex items-center shrink-0 rounded-md border border-secondary bg-secondary px-2 py-0.5 text-xs font-medium text-secondary shadow-xs hover:bg-secondary_hover transition-colors truncate max-w-[100px]"
                                      >
                                        {t}
                                      </span>
                                    ))}
                                    {extraTags > 0 && (
                                      <span
                                        className="inline-flex items-center shrink-0 rounded-md border border-secondary bg-secondary px-1.5 py-0.5 text-xs font-medium text-tertiary shadow-xs"
                                        title={(rule.tags ?? []).slice(maxTags).join(', ')}
                                      >
                                        +{extraTags}
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td className="px-4 py-3 text-right">
                                  <div className="flex items-center justify-end gap-1.5">
                                    <Link
                                      to={`/rules/${encodeURIComponent(rule.key)}`}
                                      state={{ from: detailFrom }}
                                      aria-label={`View details for ${rule.name}`}
                                      title="Open detail page"
                                      className="rounded p-1 text-quaternary transition-colors hover:bg-secondary hover:text-brand-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      <ArrowUpRight className="size-4" />
                                    </Link>
                                    <ChevronDown
                                      className={cn(
                                        'size-4 text-quaternary transition-transform duration-200',
                                        isExpanded && 'rotate-180 text-brand-secondary'
                                      )}
                                      aria-hidden="true"
                                    />
                                  </div>
                                </td>
                              </tr>
                              {isExpanded && (
                                <tr role="row">
                                  <td colSpan={6} className="border-t border-brand/20 bg-secondary/15 px-5 py-4 whitespace-normal">
                                    <RuleInlineDetail ruleKey={rule.key} initialDescription={rule.description} />
                                  </td>
                                </tr>
                              )}
                            </Fragment>
                          )
                        })}
                      </tbody>
                    </table>

                    {/* Pagination Bar */}
                    {resultRules.length > 0 && (
                      <div className="flex flex-col gap-3 border-t border-secondary px-5 py-3 sm:flex-row sm:items-center sm:justify-between bg-primary">
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="text-xs text-tertiary">
                            Showing <span className="font-semibold text-primary">{(page - 1) * pageSize + 1}</span> to{' '}
                            <span className="font-semibold text-primary">{Math.min(page * pageSize, resultRules.length)}</span> of{' '}
                            <span className="font-semibold text-primary">{resultRules.length.toLocaleString()}</span> rules
                          </span>
                          <div className="flex items-center gap-1.5 text-xs text-tertiary">
                            <span>Per page:</span>
                            <select
                              value={pageSize}
                              onChange={(e) => {
                                setPageSize(Number(e.target.value))
                                setPage(1)
                              }}
                              aria-label="Rules per page"
                              className="rounded border border-secondary bg-primary px-2 py-1 text-xs font-medium text-primary shadow-xs focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand"
                            >
                              <option value={25}>25</option>
                              <option value={50}>50</option>
                              <option value={100}>100</option>
                            </select>
                          </div>
                        </div>

                        {totalPages > 1 && (
                          <div className="flex items-center gap-2">
                            <Button
                              variant="secondary"
                              disabled={page <= 1}
                              onClick={() => setPage((p) => Math.max(1, p - 1))}
                              className="h-8 px-2.5 text-xs"
                              aria-label="Previous page"
                            >
                              Previous
                            </Button>
                            <span className="text-xs font-medium text-tertiary">
                              Page <span className="font-semibold text-primary">{page}</span> of{' '}
                              <span className="font-semibold text-primary">{totalPages}</span>
                            </span>
                            <Button
                              variant="secondary"
                              disabled={page >= totalPages}
                              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                              className="h-8 px-2.5 text-xs"
                              aria-label="Next page"
                            >
                              Next
                            </Button>
                          </div>
                        )}
                      </div>
                    )}
                  </Card>
                </div>

                {/* Mobile Cards */}
                <VirtualRuleCards
                  rules={resultRules}
                  detailFrom={detailFrom}
                />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
