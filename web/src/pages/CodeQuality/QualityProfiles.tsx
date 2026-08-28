import { useEffect, useMemo, useState } from 'react'
import {
  FileCode01,
  LayersThree01,
  SearchLg,
  ShieldTick,
  ShieldZap,
  XClose,
} from '@untitledui/icons'
import { api } from '../../lib/api'
import type { QualityProfile } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Input, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { ProfileDetail } from './components/ProfileDetail'
import type { TypeFilter } from './components/qualityProfileTypes'

export function QualityProfiles() {
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')

  const { data: profiles, error: err } = useFetch<QualityProfile[]>(
    () => api.listQualityProfiles(),
    { deps: [refresh] },
  )

  // Auto-select first profile when profiles load or if current selection is invalid
  useEffect(() => {
    if (!profiles || profiles.length === 0) return
    if (!selectedKey || !profiles.some((p) => p.key === selectedKey)) {
      setSelectedKey(profiles[0].key)
    }
  }, [profiles, selectedKey])

  // Aggregate stats for KPI cards
  const stats = useMemo(() => {
    if (!profiles) return { total: 0, languages: 0, builtIn: 0, custom: 0 }
    const languages = new Set(profiles.map((p) => p.language)).size
    const builtIn = profiles.filter((p) => p.builtIn).length
    const custom = profiles.filter((p) => !p.builtIn).length
    return {
      total: profiles.length,
      languages,
      builtIn,
      custom,
    }
  }, [profiles])

  // Filtered profiles for Master Sidebar
  const filteredProfiles = useMemo(() => {
    if (!profiles) return []
    const q = searchQuery.trim().toLowerCase()
    return profiles.filter((p) => {
      // Type filter
      if (typeFilter === 'builtin' && !p.builtIn) return false
      if (typeFilter === 'custom' && p.builtIn) return false

      // Search query (profile name, key, or language)
      if (!q) return true
      return (
        p.name.toLowerCase().includes(q) ||
        p.key.toLowerCase().includes(q) ||
        p.language.toLowerCase().includes(q)
      )
    })
  }, [profiles, searchQuery, typeFilter])

  // Group filtered profiles by language
  const byLanguage = useMemo(() => {
    const map = new Map<string, QualityProfile[]>()
    for (const p of filteredProfiles) {
      const list = map.get(p.language) ?? []
      list.push(p)
      map.set(p.language, list)
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [filteredProfiles])

  const selected = profiles?.find((p) => p.key === selectedKey) ?? null

  if (err) {
    return (
      <div className="space-y-3">
        <ErrorState message={err} />
        <Button variant="secondary" onClick={() => setRefresh((c) => c + 1)}>
          Retry
        </Button>
      </div>
    )
  }

  if (!profiles) {
    return (
      <div className="flex h-40 items-center justify-center">
        <Spinner label="Loading quality profiles…" />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Quality Profiles</h1>
        </div>
      </header>

      {/* Top KPI Stat Cards (DESIGN-REFERENCE.md standard) */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        {/* Total Profiles */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Total Profiles</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.total}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <LayersThree01 className="size-5 text-brand-secondary" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Languages */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Languages</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.languages}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <FileCode01 className="size-5 text-utility-blue-600 dark:text-utility-blue-400" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Built-in Profiles */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Built-in Defaults</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.builtIn}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <ShieldTick className="size-5 text-utility-green-600 dark:text-utility-green-400" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Custom Profiles */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold text-secondary">Custom Profiles</span>
              <div className="mt-2 font-mono text-3xl font-bold tabular-nums text-primary sm:text-4xl">
                {stats.custom}
              </div>
            </div>
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs">
              <ShieldZap className="size-5 text-utility-orange-600 dark:text-utility-orange-400" aria-hidden="true" />
            </span>
          </div>
        </div>
      </div>

      {/* Main Master-Detail Layout aligned with 4-col KPI grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4 items-start">
        {/* Left Column: Master Sidebar with Internal Sticky Scroll */}
        <aside
          className="w-full rounded-xl border border-secondary bg-primary shadow-xs lg:sticky lg:top-4 lg:max-h-[calc(100vh-220px)] flex flex-col overflow-hidden"
          aria-label="Quality profiles master list"
        >
          {/* Master Toolbar: Search & Segmented Filter */}
          <div className="border-b border-secondary bg-secondary/20 p-3 space-y-2.5">
            {/* Search Input */}
            <div className="relative">
              <SearchLg className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-tertiary" aria-hidden="true" />
              <Input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search profile or language…"
                className="h-8 pl-8 pr-7 text-xs font-medium"
                aria-label="Search profiles or languages"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary transition hover:text-primary"
                >
                  <XClose className="size-3" />
                </button>
              )}
            </div>

            {/* Segmented Filter Pills */}
            <div className="flex items-center rounded-lg border border-secondary bg-secondary/30 p-0.5 shadow-xs">
              <button
                type="button"
                onClick={() => setTypeFilter('all')}
                className={cn(
                  'flex-1 rounded-md py-1 text-center text-[11px] font-semibold transition-all',
                  typeFilter === 'all'
                    ? 'bg-primary text-primary shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary'
                )}
              >
                All <span className="font-mono tabular-nums text-quaternary">({profiles.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setTypeFilter('builtin')}
                className={cn(
                  'flex-1 rounded-md py-1 text-center text-[11px] font-semibold transition-all',
                  typeFilter === 'builtin'
                    ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary'
                )}
              >
                Built-in <span className="font-mono tabular-nums text-quaternary">({stats.builtIn})</span>
              </button>
              <button
                type="button"
                onClick={() => setTypeFilter('custom')}
                className={cn(
                  'flex-1 rounded-md py-1 text-center text-[11px] font-semibold transition-all',
                  typeFilter === 'custom'
                    ? 'bg-primary text-utility-blue-700 dark:text-utility-blue-300 shadow-xs border border-secondary/60'
                    : 'text-tertiary hover:text-primary'
                )}
              >
                Custom <span className="font-mono tabular-nums text-quaternary">({stats.custom})</span>
              </button>
            </div>
          </div>

          {/* Scrollable Master List Area */}
          <div className="flex-1 overflow-y-auto p-2.5 space-y-4">
            {byLanguage.length === 0 ? (
              <div className="py-6 text-center">
                <EmptyState
                  icon={ShieldTick}
                  title="No matching profiles"
                  hint={searchQuery ? 'Try adjusting your search or filter.' : 'No profiles found.'}
                />
                {searchQuery && (
                  <Button
                    variant="secondary"
                    className="mt-3 text-xs"
                    onClick={() => {
                      setSearchQuery('')
                      setTypeFilter('all')
                    }}
                  >
                    Reset filters
                  </Button>
                )}
              </div>
            ) : (
              byLanguage.map(([lang, list]) => (
                <div key={lang} className="space-y-1.5">
                  {/* Language Section Header */}
                  <div className="flex items-center justify-between px-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
                    <span className="truncate">{lang}</span>
                    <span className="text-[10px] font-mono text-tertiary tabular-nums">
                      {list.length} {list.length === 1 ? 'profile' : 'profiles'}
                    </span>
                  </div>

                  {/* Profile Items */}
                  <ul className="space-y-1">
                    {list.map((p) => {
                      const isSelected = p.key === selectedKey
                      const activeRuleCount = Object.keys(p.activatedRules ?? {}).length
                      return (
                        <li key={p.key}>
                          <button
                            type="button"
                            onClick={() => setSelectedKey(p.key)}
                            aria-pressed={isSelected}
                            className={cn(
                              'group flex w-full flex-col gap-1 rounded-lg border px-3 py-2 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
                              isSelected
                                ? 'border-brand-solid bg-brand-primary/10 shadow-xs ring-1 ring-brand-solid'
                                : 'border-secondary bg-primary hover:bg-secondary/40'
                            )}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span
                                className={cn(
                                  'min-w-0 flex-1 truncate text-xs font-semibold',
                                  isSelected ? 'text-brand-secondary' : 'text-primary group-hover:text-primary'
                                )}
                                title={p.name}
                              >
                                {p.name}
                              </span>
                              {p.builtIn ? (
                                <span className="shrink-0 whitespace-nowrap inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold bg-brand-primary/20 text-brand-secondary border border-brand/30">
                                  Built-in
                                </span>
                              ) : (
                                <span className="shrink-0 whitespace-nowrap inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold bg-utility-blue-50 text-utility-blue-700 border border-utility-blue-200 dark:bg-utility-blue-950/40 dark:text-utility-blue-300 dark:border-utility-blue-800">
                                  Custom
                                </span>
                              )}
                            </div>

                            {/* Subtitle with key and active count */}
                            <div className="flex items-center justify-between gap-2 text-[11px]">
                              <span className="min-w-0 font-mono text-tertiary italic truncate" title={p.key}>
                                {p.key}
                              </span>
                              <span className="shrink-0 whitespace-nowrap inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold bg-utility-green-50 text-utility-green-700 border border-utility-green-200 dark:bg-utility-green-950/40 dark:text-utility-green-300 tabular-nums">
                                {activeRuleCount} active
                              </span>
                            </div>
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                </div>
              ))
            )}
          </div>

          {/* Footer summary in Master Sidebar */}
          <div className="border-t border-secondary bg-secondary/10 px-3 py-2 text-[11px] text-tertiary flex items-center justify-between">
            <span>Showing {filteredProfiles.length} profiles</span>
            <span className="font-mono">{byLanguage.length} stacks</span>
          </div>
        </aside>

        {/* Right Column: Profile Detail (3 cols) */}
        <main className="min-w-0 lg:col-span-3">
          {selected ? (
            <ProfileDetail
              key={selected.key}
              profile={selected}
              onChanged={() => setRefresh((c) => c + 1)}
            />
          ) : (
            <Card title="Select a profile">
              <EmptyState
                icon={ShieldTick}
                title="No profile selected"
                hint="Choose a profile from the list on the left to view and edit its rules."
              />
            </Card>
          )}
        </main>
      </div>
    </div>
  )
}
