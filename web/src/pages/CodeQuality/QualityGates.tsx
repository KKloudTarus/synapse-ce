import { Edit01, Plus, ShieldTick, Trash01, XClose } from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import type { QualityGate, QualityGateCondition } from '../../lib/types'
import { metricLabel } from '../../components/codequality/qualityPresentation'
import { Button, Card, EmptyState, ErrorState, Input, Pill, Select, Spinner } from '../../components/ui'

const metrics = ['new_critical', 'new_high', 'new_medium', 'new_secret', 'new_vulnerability', 'new_issues', 'total_critical', 'coverage', 'new_coverage', 'duplication_density', 'new_duplication', 'security_rating', 'reliability_rating', 'maintainability_rating', 'security_hotspots_reviewed', 'new_security_hotspots_reviewed']
const operators: QualityGateCondition['op'][] = ['<=', '>=', '==', '<', '>']
const blankCondition = (): QualityGateCondition => ({ metric: 'new_high', op: '<=', threshold: 0 })

export function QualityGates() {
  const [gates, setGates] = useState<QualityGate[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<QualityGate | 'new' | null>(null)
  const [refresh, setRefresh] = useState(0)

  const { data: fetchedGates, error: fetchError } = useFetch(
    () => api.listQualityGates(),
    { deps: [refresh] },
  )

  useEffect(() => { if (fetchedGates) setGates(fetchedGates) }, [fetchedGates])
  useEffect(() => { if (fetchError) setError(fetchError) }, [fetchError])

  function load() { setRefresh((c) => c + 1) }

  async function remove(gate: QualityGate) {
    if (!window.confirm(`Delete “${gate.name}”? Assigned gates cannot be deleted.`)) return
    setError(null)
    try {
      await api.deleteQualityGate(gate.key)
      if (editing !== 'new' && editing?.key === gate.key) setEditing(null)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete quality gate')
    }
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Quality Gates</h1>
          <p className="mt-1 text-sm text-secondary">Define release policies with measurable conditions and assign them to Projects</p>
        </div>
        <Button
          variant="secondary"
          className={editing ? '!border-brand-solid !text-brand-secondary hover:!border-brand-solid hover:!bg-brand-primary/10 hover:!text-brand-primary' : '!bg-brand-solid !text-white hover:!bg-brand-solid_hover'}
          onClick={() => setEditing(editing ? null : 'new')}
        >
          {editing ? <><XClose className="size-4" /> Cancel</> : <><Plus className="size-4" /> New gate</>}
        </Button>
      </header>

      {editing && <GateEditor key={editing === 'new' ? 'new' : editing.key} gate={editing === 'new' ? null : editing} onSaved={() => { setEditing(null); load() }} />}
      {error && <div className="mb-6"><ErrorState message={error} /><Button className="mt-3" variant="secondary" onClick={load}>Retry</Button></div>}
      {!gates && !error && <Spinner label="Loading quality gates…" />}
      {gates?.length === 0 && <EmptyState icon={ShieldTick} title="No quality gates" hint="Create a custom gate or use the built-in default." />}
      {gates && gates.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2">
          {gates.map((gate) => (
            <Card key={gate.key} title={gate.name} actions={<Pill className="tabular-nums">{gate.builtIn ? 'Built-in' : 'Custom'} · {gate.conditions.length} conditions</Pill>} className={gate.builtIn ? 'border-brand/20' : undefined}>
              <ul className="space-y-2">
                {gate.conditions.map((condition, index) => (
                  <li key={`${condition.metric}-${index}`} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-secondary bg-secondary/40 px-3 py-2.5">
                    <span className="text-sm font-medium text-primary">{metricLabel(condition.metric)}</span>
                    <span className="font-mono tabular-nums text-xs text-tertiary">{condition.op} {condition.threshold}</span>
                  </li>
                ))}
              </ul>
              {gate.builtIn ? (
                <p className="mt-4 text-xs text-tertiary">Built-in policy maintained by Synapse</p>
              ) : (
                <div className="mt-4 flex gap-2">
                  <Button
                    variant="secondary"
                    className="!border-brand-solid !text-brand-secondary hover:!border-brand-solid hover:!bg-brand-primary/10 hover:!text-brand-primary"
                    onClick={() => setEditing(gate)}
                  >
                    <Edit01 className="size-4" aria-hidden="true" /> Edit
                  </Button>
                  <Button
                    variant="secondary"
                    className="!border-utility-red-400 !text-utility-red-600 hover:!border-utility-red-600 hover:!bg-utility-red-50 hover:!text-utility-red-700 dark:border-utility-red-800 dark:text-utility-red-400 dark:hover:!bg-utility-red-950/40 dark:hover:!text-utility-red-300"
                    onClick={() => remove(gate)}
                  >
                    <Trash01 className="size-4" aria-hidden="true" /> Delete
                  </Button>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

function GateEditor({ gate, onSaved }: { gate: QualityGate | null; onSaved: () => void }) {
  const [key, setKey] = useState(gate?.key ?? '')
  const [name, setName] = useState(gate?.name ?? '')
  const [conditions, setConditions] = useState<QualityGateCondition[]>(gate?.conditions.map((condition) => ({ ...condition })) ?? [blankCondition()])
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  function update(index: number, next: Partial<QualityGateCondition>) {
    setConditions((current) => current.map((condition, i) => i === index ? { ...condition, ...next } : condition))
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
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

  return (
    <Card title={gate ? `Edit ${gate.name}` : 'New quality gate'} className="mb-6">
      <form className="space-y-4" onSubmit={submit}>
        <div className="grid gap-3 sm:grid-cols-2">
          <label htmlFor="gate-name" className="block space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">
              <span>Name</span>
            </div>
            <Input id="gate-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Standard Release" className="h-10" autoFocus />
          </label>

          <label htmlFor="gate-key" className="block space-y-1.5">
            <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-tertiary">
              <span>Key</span>
              <span className="text-[10px] font-normal normal-case text-quaternary">{gate ? 'Immutable' : 'lowercase-hyphenated'}</span>
            </div>
            <Input id="gate-key" value={key} disabled={!!gate} onChange={(event) => setKey(event.target.value)} placeholder="e.g. standard-release" className="h-10" />
          </label>
        </div>

        <div className="space-y-2.5 pt-1">
          <div className="flex items-center justify-between">
            <div className="text-xs font-semibold uppercase tracking-wider text-tertiary">
              Conditions <span className="font-mono tabular-nums text-quaternary">({conditions.length})</span>
            </div>
            <Button
              type="button"
              variant="secondary"
              className="h-7 !border-brand-solid px-2 text-xs font-semibold !text-brand-secondary hover:!border-brand-solid hover:!bg-brand-primary/10 hover:!text-brand-primary"
              onClick={() => setConditions((current) => [...current, blankCondition()])}
            >
              <Plus className="size-3.5" aria-hidden="true" /> Add condition
            </Button>
          </div>

          <div className="space-y-2">
            {conditions.map((condition, index) => (
              <div
                key={index}
                className="flex flex-wrap items-center gap-2 rounded-lg border border-secondary bg-secondary/20 p-2 sm:flex-nowrap sm:gap-2.5 sm:px-3 sm:py-2"
              >
                <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-secondary text-[11px] font-bold text-tertiary">
                  {index + 1}
                </span>

                <div className="min-w-[180px] flex-1">
                  <Select
                    id={`gate-metric-${index}`}
                    value={condition.metric}
                    onValueChange={(value) => update(index, { metric: value })}
                    ariaLabel={`Condition ${index + 1} metric`}
                    options={metrics.map((value) => ({ value, label: metricLabel(value) }))}
                    size="sm"
                    className="w-full bg-primary"
                  />
                </div>

                <div className="w-20 shrink-0">
                  <Select
                    id={`gate-op-${index}`}
                    value={condition.op}
                    onValueChange={(value) => update(index, { op: value as QualityGateCondition['op'] })}
                    ariaLabel={`Condition ${index + 1} operator`}
                    options={operators.map((value) => ({ value, label: value }))}
                    size="sm"
                    className="w-full bg-primary font-mono"
                  />
                </div>

                <div className="w-24 shrink-0">
                  <Input
                    id={`gate-threshold-${index}`}
                    type="number"
                    step="any"
                    value={condition.threshold}
                    onChange={(event) => update(index, { threshold: event.target.value === '' ? Number.NaN : Number(event.target.value) })}
                    className="h-8 py-1 text-xs"
                    placeholder="0"
                  />
                </div>

                <button
                  type="button"
                  disabled={conditions.length === 1}
                  onClick={() => setConditions((current) => current.filter((_, i) => i !== index))}
                  aria-label={`Remove condition ${index + 1}`}
                  className="flex size-8 shrink-0 items-center justify-center rounded-lg text-tertiary transition hover:bg-secondary hover:text-utility-red-600 disabled:cursor-not-allowed disabled:opacity-30"
                >
                  <Trash01 className="size-4" aria-hidden="true" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {error && <ErrorState message={error} />}
        <div className="flex justify-end pt-2">
          <Button variant="brand" type="submit" loading={saving} className="h-9 px-4 text-xs font-semibold">
            {gate ? 'Save changes' : 'Create gate'}
          </Button>
        </div>
      </form>
    </Card>
  )
}
