import { Plus, ShieldTick, Trash01, XClose } from '@untitledui/icons'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { metricLabel } from '../../../components/codequality/qualityPresentation'
import { Button, ErrorState, Input, Select, cn } from '../../../components/ui'
import { api } from '../../../lib/api'
import type { QualityGate, QualityGateCondition } from '../../../lib/types'
import { blankCondition, getMetricCategory, getMetricCategoryStyle, metrics, operators } from './qualityGateHelpers'

export function GateEditorModal({
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
        <div className="flex items-center justify-between border-b border-secondary px-6 py-4 bg-secondary">
          <div className="flex items-center gap-3">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-secondary bg-primary text-brand-secondary shadow-2xs">
              <ShieldTick className="size-5" aria-hidden="true" />
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
              <Button variant="primary" type="submit" loading={saving} className="h-9 px-5 text-xs font-semibold">
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
