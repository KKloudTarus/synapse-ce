import {
  Award01,
  Edit01,
  FileCode01,
  Percent01,
  Plus,
  SearchLg,
  ShieldTick,
  ShieldZap,
  Trash01,
  XClose,
} from '@untitledui/icons'
import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import type { QualityGate, QualityGateCondition } from '../../lib/types'
import { metricLabel } from '../../components/codequality/qualityPresentation'
import { Button, Card, EmptyState, ErrorState, Input, Select, Spinner, cn } from '../../components/ui'

const metrics = [
  'new_critical',
  'new_high',
  'new_medium',
  'new_secret',
  'new_vulnerability',
  'new_issues',
  'total_critical',
  'coverage',
  'new_coverage',
  'duplication_density',
  'new_duplication',
  'security_rating',
  'reliability_rating',
  'maintainability_rating',
  'security_hotspots_reviewed',
  'new_security_hotspots_reviewed',
]
const operators: QualityGateCondition['op'][] = ['<=', '>=', '==', '<', '>']
const blankCondition = (metric = 'new_high'): QualityGateCondition => ({ metric, op: '<=', threshold: 0 })

type MetricCategory = 'security' | 'rating' | 'coverage' | 'duplication'
type TypeFilter = 'all' | 'builtin' | 'custom'
type SortOption = 'name-asc' | 'name-desc' | 'conditions-desc' | 'conditions-asc'

function getMetricCategory(metric: string): MetricCategory {
  if (['new_critical', 'new_high', 'new_medium', 'new_secret', 'new_vulnerability', 'total_critical'].includes(metric)) {
    return 'security'
  }
  if (
    [
      'security_rating',
      'reliability_rating',
      'maintainability_rating',
      'security_hotspots_reviewed',
      'new_security_hotspots_reviewed',
    ].includes(metric)
  ) {
    return 'rating'
  }
  if (['coverage', 'new_coverage'].includes(metric)) {
    return 'coverage'
  }
  return 'duplication'
}

function getMetricCategoryStyle(category: MetricCategory) {
  switch (category) {
    case 'security':
      return {
        cardBg: 'border-utility-pink-200 bg-utility-pink-50/50 dark:border-utility-pink-800 dark:bg-utility-pink-950/20',
        icon: ShieldZap,
        iconBg: 'bg-utility-pink-100 text-utility-pink-700 dark:bg-utility-pink-900/40 dark:text-utility-pink-300',
      }
    case 'rating':
      return {
        cardBg: 'border-utility-orange-200 bg-utility-orange-50/50 dark:border-utility-orange-800 dark:bg-utility-orange-950/20',
        icon: Award01,
        iconBg: 'bg-utility-orange-100 text-utility-orange-700 dark:bg-utility-orange-900/40 dark:text-utility-orange-300',
      }
    case 'coverage':
      return {
        cardBg: 'border-utility-green-200 bg-utility-green-50/50 dark:border-utility-green-800 dark:bg-utility-green-950/20',
        icon: Percent01,
        iconBg: 'bg-utility-green-100 text-utility-green-700 dark:bg-utility-green-900/40 dark:text-utility-green-300',
      }
    case 'duplication':
    default:
      return {
        cardBg: 'border-utility-blue-200 bg-utility-blue-50/50 dark:border-utility-blue-800 dark:bg-utility-blue-950/20',
        icon: FileCode01,
        iconBg: 'bg-utility-blue-100 text-utility-blue-700 dark:bg-utility-blue-900/40 dark:text-utility-blue-300',
      }
  }
}

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
          <p className="mt-1 text-sm text-secondary">Define release policies with measurable conditions and assign them to Projects</p>
        </div>
        <Button
          variant="brand"
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
              <div className="flex items-center rounded-lg border border-secondary bg-secondary/30 p-0.5 shadow-xs">
                <button
                  type="button"
                  onClick={() => setTypeFilter('all')}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-all',
                    typeFilter === 'all'
                      ? 'bg-primary text-primary shadow-xs border border-secondary/60'
                      : 'text-tertiary hover:text-primary'
                  )}
                >
                  All <span className="ml-1 text-[11px] font-mono text-quaternary tabular-nums">({gates.length})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTypeFilter('builtin')}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-all',
                    typeFilter === 'builtin'
                      ? 'bg-primary text-brand-secondary shadow-xs border border-secondary/60'
                      : 'text-tertiary hover:text-primary'
                  )}
                >
                  Built-in <span className="ml-1 text-[11px] font-mono text-quaternary tabular-nums">({builtInCount})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTypeFilter('custom')}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-all',
                    typeFilter === 'custom'
                      ? 'bg-primary text-utility-blue-700 dark:text-utility-blue-300 shadow-xs border border-secondary/60'
                      : 'text-tertiary hover:text-primary'
                  )}
                >
                  Custom <span className="ml-1 text-[11px] font-mono text-quaternary tabular-nums">({customCount})</span>
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
                            'flex size-9 shrink-0 items-center justify-center rounded-xl border shadow-sm transition-all',
                            gate.builtIn
                              ? 'border-brand/30 bg-brand-primary/10 text-brand-secondary ring-1 ring-brand/10'
                              : 'border-utility-blue-200 bg-utility-blue-50 text-utility-blue-700 ring-1 ring-utility-blue-100 dark:border-utility-blue-800 dark:bg-utility-blue-950/40 dark:text-utility-blue-300'
                          )}
                        >
                          <ShieldTick className="size-4.5" aria-hidden="true" />
                        </div>
                        <div className="min-w-0">
                          <span className="font-bold text-primary block leading-tight truncate">{gate.name}</span>
                          <span className="font-mono text-xs text-tertiary italic">{gate.key}</span>
                        </div>
                      </div>
                    }
                    actions={
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold shadow-xs',
                            gate.builtIn
                              ? 'border-brand/30 bg-brand-primary/15 text-brand-secondary'
                              : 'border-utility-blue-200 bg-utility-blue-50 text-utility-blue-700 dark:border-utility-blue-800 dark:bg-utility-blue-950/40 dark:text-utility-blue-300'
                          )}
                        >
                          {gate.builtIn ? 'Built-in' : 'Custom'}
                        </span>
                        <span className="inline-flex items-center rounded-md border border-secondary bg-secondary px-2 py-0.5 text-xs font-medium text-tertiary shadow-xs tabular-nums">
                          {gate.conditions.length} conditions
                        </span>
                      </div>
                    }
                    className={cn(gate.builtIn ? 'border-brand/30 shadow-xs' : 'border-secondary shadow-xs')}
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
                            <span className="shrink-0 rounded border border-secondary bg-primary px-1.5 py-0.5 font-mono text-[11px] font-bold text-primary shadow-xs tabular-nums">
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
                          className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-dashed border-secondary bg-secondary/40 py-1.5 text-xs font-medium text-secondary transition hover:border-brand-solid hover:bg-brand-primary/10 hover:text-brand-primary"
                        >
                          <span className="font-semibold">+ {gate.conditions.length - 6} more conditions</span>
                          <span className="text-[11px] font-normal text-tertiary">
                            ({gate.builtIn ? 'Click to view all' : 'Click to view & edit'})
                          </span>
                        </button>
                      </div>
                    )}

                    {gate.builtIn ? (
                      <div className="mt-3 flex items-center justify-between border-t border-secondary/60 pt-2.5">
                        <p className="text-xs text-tertiary">Built-in policy maintained by Synapse</p>
                        <span className="text-[11px] font-medium text-brand-secondary">Active Baseline</span>
                      </div>
                    ) : (
                      <div className="mt-3 flex items-center justify-end gap-2 border-t border-secondary/60 pt-2.5">
                        <Button
                          variant="secondary"
                          className="h-8 !border-brand-solid !text-brand-secondary hover:!border-brand-solid hover:!bg-brand-primary/10 hover:!text-brand-primary text-xs"
                          onClick={() => setEditing(gate)}
                        >
                          <Edit01 className="size-3.5" aria-hidden="true" /> Edit
                        </Button>
                        <Button
                          variant="secondary"
                          className="h-8 !border-utility-red-400 !text-utility-red-600 hover:!border-utility-red-600 hover:!bg-utility-red-50 hover:!text-utility-red-700 dark:border-utility-red-800 dark:text-utility-red-400 dark:hover:!bg-utility-red-950/40 dark:hover:!text-utility-red-300 text-xs"
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

function DeleteGateModal({
  gate,
  onClose,
  onDeleted,
}: {
  gate: QualityGate
  onClose: () => void
  onDeleted: () => void
}) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  async function handleDelete() {
    setDeleting(true)
    setError(null)
    try {
      await api.deleteQualityGate(gate.key)
      onDeleted()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete quality gate')
      setDeleting(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity" onClick={onClose} aria-hidden="true" />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-gate-title"
        className="relative z-10 w-full max-w-md flex flex-col rounded-2xl border border-secondary bg-primary p-6 shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        <div className="flex items-start gap-3.5">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-utility-red-200 bg-utility-red-50 text-utility-red-600 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-400 shadow-sm">
            <Trash01 className="size-5" aria-hidden="true" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 id="delete-gate-title" className="text-base font-bold text-primary">
              Delete “{gate.name}”?
            </h2>
            <p className="mt-1 text-xs text-secondary leading-relaxed">
              Are you sure you want to delete this quality gate? Assigned quality gates cannot be deleted.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1 text-tertiary transition hover:bg-secondary hover:text-primary shrink-0"
          >
            <XClose className="size-5" />
          </button>
        </div>

        {error && <div className="mt-4"><ErrorState message={error} /></div>}

        <div className="mt-6 flex items-center justify-end">
          <Button
            type="button"
            onClick={handleDelete}
            loading={deleting}
            className="h-9 px-5 text-xs font-semibold !bg-utility-red-600 !text-white hover:!bg-utility-red-700 shadow-xs"
          >
            Delete
          </Button>
        </div>
      </div>
    </div>,
    document.body
  )
}

function GateEditorModal({
  gate,
  onClose,
  onSaved,
}: {
  gate: QualityGate | null
  onClose: () => void
  onSaved: () => void
}) {
  const isBuiltIn = gate?.builtIn === true
  const [key, setKey] = useState(gate?.key ?? '')
  const [name, setName] = useState(gate?.name ?? '')
  const [conditions, setConditions] = useState<QualityGateCondition[]>(
    gate?.conditions.map((condition) => ({ ...condition })) ?? [blankCondition()]
  )
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setKey(gate?.key ?? '')
    setName(gate?.name ?? '')
    setConditions(gate?.conditions.map((c) => ({ ...c })) ?? [blankCondition()])
    setError(null)
  }, [gate])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  function update(index: number, next: Partial<QualityGateCondition>) {
    setConditions((current) => current.map((condition, i) => (i === index ? { ...condition, ...next } : condition)))
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (isBuiltIn) {
      onClose()
      return
    }
    const cleanName = name.trim()
    const cleanKey = key.trim()
    if (!cleanName || !cleanKey) {
      setError('Name and key are required.')
      return
    }
    if (conditions.length === 0) {
      setError('Add at least one condition.')
      return
    }
    if (conditions.some((condition) => !Number.isFinite(condition.threshold))) {
      setError('Every threshold must be a finite number.')
      return
    }
    setSaving(true)
    setError(null)
    try {
      if (gate) await api.updateQualityGate(gate.key, { name: cleanName, conditions })
      else await api.createQualityGate({ key: cleanKey, name: cleanName, conditions })
      onSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save quality gate')
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity" onClick={onClose} aria-hidden="true" />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="gate-modal-title"
        className="relative z-10 w-full max-w-2xl max-h-[90vh] flex flex-col rounded-2xl border border-secondary bg-primary shadow-2xl overflow-hidden animate-scale-in text-left"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary/30">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                'flex size-9 shrink-0 items-center justify-center rounded-xl border shadow-sm',
                isBuiltIn
                  ? 'border-brand/30 bg-brand-primary/10 text-brand-secondary'
                  : 'border-brand/30 bg-brand-primary/10 text-brand-secondary'
              )}
            >
              <ShieldTick className="size-4.5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="gate-modal-title" className="text-lg font-bold text-primary">
                {gate ? (isBuiltIn ? `${gate.name} (Built-in)` : `Edit ${gate.name}`) : 'New Quality Gate'}
              </h2>
              <p className="text-xs text-tertiary">
                {isBuiltIn
                  ? 'Built-in baseline release criteria maintained by Synapse'
                  : gate
                  ? 'Update criteria and conditions for this release gate'
                  : 'Define new release criteria and thresholds'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1 text-tertiary transition hover:bg-secondary hover:text-primary"
          >
            <XClose className="size-5" />
          </button>
        </div>

        {/* Modal Body / Form */}
        <form onSubmit={submit} className="flex-1 overflow-y-auto p-6 space-y-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <label htmlFor="gate-name" className="block space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">
                <span>Name</span>
              </div>
              <Input
                id="gate-name"
                value={name}
                disabled={isBuiltIn}
                onChange={(event) => setName(event.target.value)}
                placeholder="e.g. Standard Release"
                className="h-10 font-medium"
                autoFocus={!isBuiltIn}
              />
            </label>

            <label htmlFor="gate-key" className="block space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-tertiary">
                <span>Key</span>
                <span className="text-[10px] font-normal normal-case text-quaternary">
                  {gate ? 'Immutable' : 'lowercase-hyphenated'}
                </span>
              </div>
              <Input
                id="gate-key"
                value={key}
                disabled={!!gate}
                onChange={(event) => setKey(event.target.value)}
                placeholder="e.g. standard-release"
                className="h-10 font-mono"
              />
            </label>
          </div>

          <div className="space-y-3 pt-1">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold uppercase tracking-wider text-tertiary">
                Conditions <span className="font-mono tabular-nums text-quaternary">({conditions.length})</span>
              </div>
              {!isBuiltIn && (
                <Button
                  type="button"
                  variant="secondary"
                  className="h-7.5 !border-brand-solid px-2.5 text-xs font-semibold !text-brand-secondary hover:!border-brand-solid hover:!bg-brand-primary/10 hover:!text-brand-primary"
                  onClick={() => {
                    const unused = metrics.find((m) => !conditions.some((c) => c.metric === m)) ?? 'new_issues'
                    setConditions((current) => [...current, blankCondition(unused)])
                  }}
                >
                  <Plus className="size-3.5" aria-hidden="true" /> Add condition
                </Button>
              )}
            </div>

            <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
              {conditions.map((condition, index) => {
                const cat = getMetricCategory(condition.metric)
                const style = getMetricCategoryStyle(cat)
                const Icon = style.icon

                return (
                  <div
                    key={index}
                    className="flex flex-wrap items-center gap-2 rounded-xl border border-secondary bg-secondary/20 p-2 sm:flex-nowrap sm:gap-2.5 sm:px-3 sm:py-2 shadow-xs"
                  >
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-secondary text-[11px] font-bold text-tertiary">
                        {index + 1}
                      </span>
                      <div className={cn('flex size-6 shrink-0 items-center justify-center rounded-md', style.iconBg)}>
                        <Icon className="size-3.5" aria-hidden="true" />
                      </div>
                    </div>

                    <div className="min-w-[180px] flex-1">
                      {isBuiltIn ? (
                        <div className="h-8 rounded-lg border border-secondary bg-primary px-3 flex items-center text-xs font-medium text-primary">
                          {metricLabel(condition.metric)}
                        </div>
                      ) : (
                        <Select
                          id={`gate-metric-${index}`}
                          value={condition.metric}
                          onValueChange={(value) => update(index, { metric: value })}
                          ariaLabel={`Condition ${index + 1} metric`}
                          options={metrics.map((value) => ({ value, label: metricLabel(value) }))}
                          size="sm"
                          className="w-full bg-primary font-medium"
                        />
                      )}
                    </div>

                    <div className="w-20 shrink-0">
                      {isBuiltIn ? (
                        <div className="h-8 rounded-lg border border-secondary bg-primary px-3 flex items-center justify-center text-xs font-mono font-bold text-primary">
                          {condition.op}
                        </div>
                      ) : (
                        <Select
                          id={`gate-op-${index}`}
                          value={condition.op}
                          onValueChange={(value) => update(index, { op: value as QualityGateCondition['op'] })}
                          ariaLabel={`Condition ${index + 1} operator`}
                          options={operators.map((value) => ({ value, label: value }))}
                          size="sm"
                          className="w-full bg-primary font-mono"
                        />
                      )}
                    </div>

                    <div className="w-24 shrink-0">
                      {isBuiltIn ? (
                        <div className="h-8 rounded-lg border border-secondary bg-primary px-3 flex items-center text-xs font-mono font-medium text-primary">
                          {condition.threshold}
                        </div>
                      ) : (
                        <Input
                          id={`gate-threshold-${index}`}
                          type="number"
                          step="any"
                          value={condition.threshold}
                          onChange={(event) =>
                            update(index, {
                              threshold: event.target.value === '' ? Number.NaN : Number(event.target.value),
                            })
                          }
                          className="h-8 py-1 text-xs font-mono font-medium"
                          placeholder="0"
                        />
                      )}
                    </div>

                    {!isBuiltIn && (
                      <button
                        type="button"
                        disabled={conditions.length === 1}
                        onClick={() => setConditions((current) => current.filter((_, i) => i !== index))}
                        aria-label={`Remove condition ${index + 1}`}
                        className="flex size-8 shrink-0 items-center justify-center rounded-lg text-tertiary transition hover:bg-secondary hover:text-utility-red-600 disabled:cursor-not-allowed disabled:opacity-30"
                      >
                        <Trash01 className="size-4" aria-hidden="true" />
                      </button>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {error && <ErrorState message={error} />}

          {/* Modal Footer Actions */}
          <div className="flex items-center justify-end border-t border-secondary pt-4">
            {isBuiltIn ? (
              <Button type="button" variant="secondary" onClick={onClose} className="h-9 px-5 text-xs font-medium">
                Close
              </Button>
            ) : (
              <Button variant="brand" type="submit" loading={saving} className="h-9 px-5 text-xs font-semibold">
                {gate ? 'Save changes' : 'Create gate'}
              </Button>
            )}
          </div>
        </form>
      </div>
    </div>,
    document.body
  )
}
