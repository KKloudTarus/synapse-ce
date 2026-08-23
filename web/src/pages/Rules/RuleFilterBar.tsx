import { SearchLg, XClose } from '@untitledui/icons'
import { FacetFilter } from '../../components/rules/FacetFilter'
import { formatRuleSeverity, formatRuleType } from '../../lib/ruleFormat'
import type { RuleFacets, RuleListFilters, RuleType, RuleSeverity } from '../../lib/types'
import type { FilterKey } from './useRulesSearch'

function formatFilterChip(key: FilterKey, val: string): string {
  if (key === 'types') return formatRuleType(val as RuleType)
  if (key === 'severities') return formatRuleSeverity(val as RuleSeverity)
  return val
}

export function RuleFilterBar({
  facets,
  filters,
  activeFilters,
  query,
  searchInputRef,
  onQueryChange,
  onFilterChange,
  onRemoveChip,
  onClearQuery,
  onClearAll,
  onSearchKey,
}: {
  facets: RuleFacets
  filters: RuleListFilters
  activeFilters: boolean
  query: string
  searchInputRef: React.RefObject<HTMLInputElement | null>
  onQueryChange: (value: string) => void
  onFilterChange: (key: FilterKey, value: string[]) => void
  onRemoveChip: (key: FilterKey, val: string) => void
  onClearQuery: () => void
  onClearAll: () => void
  onSearchKey: (e: React.KeyboardEvent<HTMLInputElement>) => void
}) {
  return (
    <>
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center">
        <div className="relative max-w-md flex-1">
          <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
          <input
            ref={searchInputRef}
            aria-label="Search rules"
            type="text"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            onKeyDown={onSearchKey}
            placeholder="Search rules..."
            className="w-full rounded-lg border border-secondary bg-primary py-2 pl-9 pr-8 text-sm text-primary transition-colors placeholder:text-placeholder focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand shadow-xs"
            maxLength={256}
          />
          {query && (
            <button
              type="button"
              onClick={onClearQuery}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
            >
              <XClose className="size-3.5" />
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <FacetFilter
            label="Language"
            values={facets.languages}
            selected={filters.languages}
            onChange={(v) => onFilterChange('languages', v)}
          />
          <FacetFilter
            label="Type"
            values={facets.types}
            selected={filters.types}
            formatValue={formatRuleType}
            onChange={(v) => onFilterChange('types', v)}
          />
          <FacetFilter
            label="Severity"
            values={facets.severities}
            selected={filters.severities}
            formatValue={formatRuleSeverity}
            onChange={(v) => onFilterChange('severities', v)}
          />
          <FacetFilter
            label="Tag"
            values={facets.tags}
            selected={filters.tags}
            onChange={(v) => onFilterChange('tags', v)}
          />
          <FacetFilter
            label="CWE"
            values={facets.cwe}
            selected={filters.cwe}
            onChange={(v) => onFilterChange('cwe', v)}
          />
          {activeFilters && (
            <button
              type="button"
              onClick={onClearAll}
              className="ml-2 text-sm font-semibold text-brand-secondary transition-colors hover:text-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand rounded-sm"
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
              <div key={`${key}-${val}`} className="flex items-center gap-1 rounded-md bg-brand-primary pl-2.5 pr-1 py-1 text-xs font-semibold text-brand-secondary ring-1 ring-brand/20">
                {formatFilterChip(key, val)}
                <button
                  type="button"
                  aria-label={`Remove ${formatFilterChip(key, val)} filter`}
                  onClick={() => onRemoveChip(key, val)}
                  className="rounded-full p-0.5 transition-colors hover:bg-brand/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
                >
                  <XClose className="size-3" />
                </button>
              </div>
            ))
          )}
        </div>
      )}
    </>
  )
}
