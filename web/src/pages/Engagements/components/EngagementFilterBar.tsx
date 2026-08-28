import { useEffect, useState, type FC } from 'react'
import { SearchLg, XClose } from '@untitledui/icons'
import { Select } from '@/components/base/select/select'
import type { EngagementStatusFilter } from '../types'

export interface EngagementFilterBarProps {
  search: string
  onSearchChange: (value: string) => void
  status: EngagementStatusFilter
  onStatusChange: (value: EngagementStatusFilter) => void
  scope: string
  onScopeChange: (value: string) => void
  onClear: () => void
  totalResults?: number
}

const STATUS_OPTIONS: { id: EngagementStatusFilter; label: string }[] = [
  { id: 'All', label: 'All Status' },
  { id: 'Draft', label: 'Draft' },
  { id: 'Active', label: 'Active' },
  { id: 'Completed', label: 'Completed' },
  { id: 'Archived', label: 'Archived' },
]

const SCOPE_OPTIONS: { id: string; label: string }[] = [
  { id: 'All', label: 'All Scope' },
  { id: 'repo', label: 'Repository' },
  { id: 'domain', label: 'Domain' },
  { id: 'host', label: 'Host' },
  { id: 'url', label: 'URL' },
  { id: 'image', label: 'Container Image' },
  { id: 'cidr', label: 'CIDR / IP' },
]

export const EngagementFilterBar: FC<EngagementFilterBarProps> = ({
  search,
  onSearchChange,
  status,
  onStatusChange,
  scope,
  onScopeChange,
  onClear,
  totalResults,
}) => {
  const [localSearch, setLocalSearch] = useState(search)

  // Debounce search input by 300ms
  useEffect(() => {
    setLocalSearch(search)
  }, [search])

  useEffect(() => {
    const handler = setTimeout(() => {
      if (localSearch !== search) {
        onSearchChange(localSearch)
      }
    }, 300)
    return () => clearTimeout(handler)
  }, [localSearch, search, onSearchChange])

  const hasActiveFilters = Boolean(search.trim() || status !== 'All' || scope !== 'All')

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex flex-1 flex-wrap items-center gap-3">
        {/* Search input with leading icon */}
        <div className="relative min-w-[240px] max-w-md flex-1">
          <SearchLg
            className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary"
            aria-hidden="true"
          />
          <input
            type="text"
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
            placeholder="Search engagements..."
            aria-label="Search engagements by name, repository or client"
            className="w-full rounded-lg border border-primary bg-primary py-2 pl-9 pr-8 text-sm text-primary placeholder:text-placeholder shadow-xs outline-none transition duration-100 ease-linear hover:border-border-primary focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
          {localSearch && (
            <button
              type="button"
              onClick={() => {
                setLocalSearch('')
                onSearchChange('')
              }}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-md p-0.5 text-quaternary hover:text-primary"
              aria-label="Clear search text"
            >
              <XClose className="size-3.5" />
            </button>
          )}
        </div>

        {/* Status Dropdown */}
        <div className="w-36 sm:w-40">
          <Select
            size="sm"
            selectedKey={status}
            onSelectionChange={(key) => onStatusChange(String(key) as EngagementStatusFilter)}
            aria-label="Filter by status"
            items={STATUS_OPTIONS}
          >
            {(item) => (
              <Select.Item id={item.id} key={item.id} label={item.label}>
                {item.label}
              </Select.Item>
            )}
          </Select>
        </div>

        {/* Scope Dropdown */}
        <div className="w-36 sm:w-44">
          <Select
            size="sm"
            selectedKey={scope}
            onSelectionChange={(key) => onScopeChange(String(key))}
            aria-label="Filter by scope"
            items={SCOPE_OPTIONS}
          >
            {(item) => (
              <Select.Item id={item.id} key={item.id} label={item.label}>
                {item.label}
              </Select.Item>
            )}
          </Select>
        </div>

        {/* Clear Filters CTA */}
        {hasActiveFilters && (
          <button
            type="button"
            onClick={onClear}
            className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold text-brand-secondary hover:bg-brand-primary/10 hover:text-brand-primary"
          >
            <XClose className="size-3.5" />
            Clear filters
          </button>
        )}
      </div>

      {totalResults !== undefined && (
        <div className="text-xs font-medium text-tertiary">
          {totalResults} {totalResults === 1 ? 'engagement' : 'engagements'} found
        </div>
      )}
    </div>
  )
}
