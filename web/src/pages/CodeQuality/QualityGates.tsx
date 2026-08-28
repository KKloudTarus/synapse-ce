import { Edit01, Plus, SearchLg, ShieldTick, Trash01, XClose } from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import type { QualityGate } from '../../lib/types'
import { metricLabel } from '../../components/codequality/qualityPresentation'
import { Button, Card, EmptyState, ErrorState, Input, Select, Spinner, cn } from '../../components/ui'
import { Badge } from '../../components/base/badges/badges'
import { DeleteGateModal } from './components/DeleteGateModal'
import { GateEditorModal } from './components/GateEditorModal'
import { getMetricCategory, getMetricCategoryStyle, type SortOption, type TypeFilter } from './components/qualityGateHelpers'

export function QualityGates() {
  const [gates, setGates] = useState<QualityGate[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<QualityGate | 'new' | null>(null)
  const [deletingGate, setDeletingGate] = useState<QualityGate | null>(null)
  const [refresh, setRefresh] = useState(0)

  // Search, Filter & Sort states
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [sortBy, setSortBy] = useState<SortOption>('name-asc')

  const { data: fetchedGates, error: fetchError } = useFetch(
    () => api.listQualityGates(),
    { deps: [refresh] },
  )

  useEffect(() => { if (fetchedGates) setGates(fetchedGates) }, [fetchedGates])
  useEffect(() => { if (fetchError) setError(fetchError) }, [fetchError])

  function load() { setRefresh((c) => c + 1) }

  const builtInCount = useMemo(() => gates?.filter((g) => g.builtIn).length ?? 0, [gates])
  const customCount = useMemo(() => gates?.filter((g) => !g.builtIn).length ?? 0, [gates])

  const filteredGates = useMemo(() => {
    if (!gates) return []
    return gates
      .filter((gate) => {
        if (typeFilter === 'builtin' && !gate.builtIn) return false
        if (typeFilter === 'custom' && gate.builtIn) return false
        if (search.trim()) {
          const q = search.trim().toLowerCase()
          const nameMatch = gate.name.toLowerCase().includes(q)
          const keyMatch = gate.key.toLowerCase().includes(q)
          const metricMatch = gate.conditions.some(
            (c) => c.metric.toLowerCase().includes(q) || metricLabel(c.metric).toLowerCase().includes(q)
          )
          return nameMatch || keyMatch || metricMatch
        }
        return true
      })
      .sort((a, b) => {
        if (sortBy === 'name-asc') return a.name.localeCompare(b.name)
        if (sortBy === 'name-desc') return b.name.localeCompare(a.name)
        if (sortBy === 'conditions-desc') return b.conditions.length - a.conditions.length
        if (sortBy === 'conditions-asc') return a.conditions.length - b.conditions.length
        return 0
      })
  }, [gates, search, typeFilter, sortBy])

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Quality Gates</h1>
        </div>
        <Button
          variant="primary"
          className="!bg-brand-solid !text-white hover:!bg-brand-solid_hover shadow-xs"
          onClick={() => setEditing('new')}
        >
          <Plus className="size-4" aria-hidden="true" /> New gate
        </Button>
      </header>

      {editing && (
        <GateEditorModal
          key={editing === 'new' ? 'new' : editing.key}
          gate={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}

      {deletingGate && (
        <DeleteGateModal
          gate={deletingGate}
          onClose={() => setDeletingGate(null)}
          onDeleted={() => {
            setDeletingGate(null)
            load()
          }}
        />
      )}

      {error && <div className="mb-6"><ErrorState message={error} /><Button className="mt-3" variant="secondary" onClick={load}>Retry</Button></div>}
      {!gates && !error && <Spinner label="Loading quality gates…" />}
      {gates?.length === 0 && <EmptyState icon={ShieldTick} title="No quality gates" hint="Create a custom gate or use the built-in default." />}

      {gates && gates.length > 0 && (
        <>
          {/* Search, Filter & Sort Toolbar */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-1 flex-wrap items-center gap-3">
              {/* Search Bar */}
              <div className="relative min-w-[240px] max-w-sm flex-1">
                <SearchLg className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-tertiary" aria-hidden="true" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search gates by name, key or metric…"
                  className="h-9 pl-9 pr-8 text-xs font-medium"
                />
                {search && (
                  <button
                    type="button"
                    onClick={() => setSearch('')}
                    aria-label="Clear search"
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-tertiary transition hover:text-primary"
                  >
                    <XClose className="size-3.5" />
                  </button>
                )}
              </div>

              {/* Segmented Filter Pills */}
              <div className="flex items-center rounded-lg border border-secondary bg-secondary p-0.5 shadow-xs">
                <button
                  type="button"
                  onClick={() => setTypeFilter('all')}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-all',
                    typeFilter === 'all'
                      ? 'bg-primary text-primary shadow-xs border border-secondary'
                      : 'text-secondary hover:text-primary'
                  )}
                >
                  All <span className="ml-1 text-xs font-mono text-tertiary tabular-nums">({gates.length})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTypeFilter('builtin')}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-all',
                    typeFilter === 'builtin'
                      ? 'bg-primary text-brand-secondary shadow-xs border border-secondary'
                      : 'text-secondary hover:text-primary'
                  )}
                >
                  Built-in <span className="ml-1 text-xs font-mono text-tertiary tabular-nums">({builtInCount})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTypeFilter('custom')}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-all',
                    typeFilter === 'custom'
                      ? 'bg-primary text-utility-blue-700 dark:text-utility-blue-300 shadow-xs border border-secondary'
                      : 'text-secondary hover:text-primary'
                  )}
                >
                  Custom <span className="ml-1 text-xs font-mono text-tertiary tabular-nums">({customCount})</span>
                </button>
              </div>
            </div>

            {/* Sorting Select */}
            <div className="w-48 shrink-0">
              <Select
                value={sortBy}
                onValueChange={(value) => setSortBy(value as SortOption)}
                options={[
                  { value: 'name-asc', label: 'Name (A to Z)' },
                  { value: 'name-desc', label: 'Name (Z to A)' },
                  { value: 'conditions-desc', label: 'Most conditions' },
                  { value: 'conditions-asc', label: 'Fewest conditions' },
                ]}
                size="sm"
                className="w-full bg-primary text-xs font-medium"
                ariaLabel="Sort quality gates"
              />
            </div>
          </div>

          {/* Cards Grid or Empty Search State */}
          {filteredGates.length === 0 ? (
            <EmptyState
              icon={SearchLg}
              title="No matching quality gates"
              hint={
                search
                  ? `No quality gates found matching "${search}". Try adjusting your search query or filters.`
                  : 'No quality gates match the selected filter.'
              }
              action={
                search || typeFilter !== 'all' ? (
                  <Button
                    variant="secondary"
                    className="mt-3 text-xs font-medium"
                    onClick={() => {
                      setSearch('')
                      setTypeFilter('all')
                    }}
                  >
                    Reset filters
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="grid gap-5 lg:grid-cols-2">
              {filteredGates.map((gate) => {
                const hasMoreConditions = gate.conditions.length > 6
                const displayedConditions = gate.conditions.slice(0, 6)

                return (
                  <Card
                    key={gate.key}
                    title={
                      <div className="flex items-center gap-3">
                        <div
                          className={cn(
                            'flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-secondary shadow-2xs',
                            gate.builtIn
                              ? 'text-fg-brand-primary'
                              : 'text-utility-blue-600 dark:text-utility-blue-400'
                          )}
                        >
                          <ShieldTick className="size-5" aria-hidden="true" />
                        </div>
                        <div className="min-w-0">
                          <span className="font-bold text-primary block leading-tight truncate">{gate.name}</span>
                        </div>
                      </div>
                    }
                    actions={
                      <div className="flex items-center gap-2">
                        <Badge
                          type="pill-color"
                          color={gate.builtIn ? 'brand' : 'blue'}
                          size="sm"
                          className="font-semibold"
                        >
                          {gate.builtIn ? 'Built-in' : 'Custom'}
                        </Badge>
                        <Badge
                          type="pill-color"
                          color="gray"
                          size="sm"
                          className="font-medium font-mono tabular-nums text-tertiary"
                        >
                          {gate.conditions.length} conditions
                        </Badge>
                      </div>
                    }
                    className="border-secondary shadow-xs"
                  >
                    {/* Compact 2-column Semantic Chips Grid (Max 6 shown directly on card) */}
                    <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      {displayedConditions.map((condition, index) => {
                        const cat = getMetricCategory(condition.metric)
                        const style = getMetricCategoryStyle(cat)
                        const Icon = style.icon

                        return (
                          <li
                            key={`${condition.metric}-${index}`}
                            className={cn(
                              'flex items-center justify-between gap-2 rounded-lg border px-2.5 py-2 shadow-xs transition-colors',
                              style.cardBg
                            )}
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <div className={cn('flex size-5 shrink-0 items-center justify-center rounded', style.iconBg)}>
                                <Icon className="size-3" aria-hidden="true" />
                              </div>
                              <span className="text-xs font-semibold text-primary truncate" title={metricLabel(condition.metric)}>
                                {metricLabel(condition.metric)}
                              </span>
                            </div>
                            <span className="shrink-0 rounded border border-secondary bg-primary px-1.5 py-0.5 font-mono text-xs font-bold text-primary shadow-xs tabular-nums">
                              {condition.op} {condition.threshold}
                            </span>
                          </li>
                        )
                      })}
                    </ul>

                    {/* Show More link opening ModalForm directly */}
                    {hasMoreConditions && (
                      <div className="mt-2.5">
                        <button
                          type="button"
                          onClick={() => setEditing(gate)}
                          className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-dashed border-secondary bg-secondary py-1.5 text-xs font-semibold text-secondary transition hover:border-brand-solid hover:bg-brand-primary hover:text-brand-secondary"
                        >
                          <span>+ {gate.conditions.length - 6} more conditions</span>
                        </button>
                      </div>
                    )}

                    {gate.builtIn ? (
                      <div className="mt-3 flex items-center justify-end border-t border-secondary pt-2.5">
                        <Badge type="pill-color" color="brand" size="sm">Active Baseline</Badge>
                      </div>
                    ) : (
                      <div className="mt-3 flex items-center justify-end gap-2 border-t border-secondary pt-2.5">
                        <Button
                          variant="secondary"
                          className="h-8 text-xs font-semibold text-brand-secondary hover:text-brand-primary"
                          onClick={() => setEditing(gate)}
                        >
                          <Edit01 className="size-3.5" aria-hidden="true" /> Edit
                        </Button>
                        <Button
                          variant="secondary"
                          className="h-8 text-xs font-semibold text-error-primary hover:text-utility-red-700"
                          onClick={() => setDeletingGate(gate)}
                        >
                          <Trash01 className="size-3.5" aria-hidden="true" /> Delete
                        </Button>
                      </div>
                    )}
                  </Card>
                )
              })}
            </div>
          )}
        </>
      )}
    </div>
  )
}
