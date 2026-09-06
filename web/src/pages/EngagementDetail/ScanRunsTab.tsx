import { useMemo, useState } from 'react'
import {
  ArrowRight,
  Clock,
  Database01,
  Fingerprint02,
  Minus,
  Package,
  Percent01,
  Plus,
} from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { ScanDrift, ScanRun } from '../../lib/types'

// A scan run's reproducibility score maps to a semantic tone: a run built entirely
// from pinned inputs (100) is reproducible; a run with live inputs (osv.dev) is not.
function reproTone(score: number): string {
  if (score >= 90) return 'text-success-primary bg-success-primary/10 border-success-primary/25'
  if (score >= 60) return 'text-warning-primary bg-warning-primary/10 border-warning-primary/25'
  return 'text-error-primary bg-error-primary/10 border-error-primary/25'
}

function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 8)}…` : id
}

function formatWhen(iso: string): string {
  if (!iso) return 'unknown time'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function RunRow({
  run,
  order,
  selected,
  disabled,
  onToggle,
}: {
  run: ScanRun
  order: number | null
  selected: boolean
  disabled: boolean
  onToggle: () => void
}) {
  const findings = run.findingKeys.length
  const pinned = run.manifest.pinnedInputs.length
  const unpinned = run.manifest.unpinnedInputs.length
  const role = order === 1 ? 'A' : order === 2 ? 'B' : null
  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled}
      aria-pressed={selected}
      aria-label={`Scan run ${shortId(run.id)}${role ? `, selected as comparison run ${role}` : ''}`}
      className={cn(
        'disabled:cursor-not-allowed disabled:opacity-60',
        'flex w-full flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border px-4 py-3 text-left transition-colors',
        selected
          ? 'border-brand-solid bg-brand-primary/5 ring-1 ring-inset ring-brand/25'
          : 'border-secondary bg-primary hover:bg-secondary/40',
      )}
    >
      <span
        className={cn(
          'inline-flex size-6 shrink-0 items-center justify-center rounded-md border text-[11px] font-bold',
          selected ? 'border-brand-solid text-brand-secondary' : 'border-secondary text-quaternary',
        )}
        aria-hidden
      >
        {order ? (order === 1 ? 'A' : 'B') : ''}
      </span>
      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-secondary">
        <Package className="size-3.5 text-quaternary" aria-hidden />
        {shortId(run.id)}
      </span>
      <span className="inline-flex items-center gap-1.5 text-xs text-tertiary">
        <Clock className="size-3.5" aria-hidden />
        {formatWhen(run.createdAt)}
      </span>
      <span
        className={cn(
          'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-xs font-bold',
          reproTone(run.manifest.reproScore),
        )}
        title="Reproducibility score: fraction of scan inputs that are version-pinned"
      >
        <Percent01 className="size-3" aria-hidden />
        {run.manifest.reproScore}
      </span>
      <span className="inline-flex items-center gap-1.5 text-xs text-tertiary">
        <Fingerprint02 className="size-3.5" aria-hidden />
        {findings} finding{findings === 1 ? '' : 's'}
      </span>
      <span className="ml-auto flex flex-wrap items-center gap-1.5">
        {run.manifest.grypeDBVersion && (
          <Pill className="font-mono">
            <Database01 className="size-3" aria-hidden />
            {run.manifest.grypeDBVersion}
          </Pill>
        )}
        <Pill>{pinned} pinned</Pill>
        {unpinned > 0 && <Pill className="text-warning-primary">{unpinned} live</Pill>}
      </span>
    </button>
  )
}

function KeyList({ keys, cap = 25 }: { keys: string[]; cap?: number }) {
  const shown = keys.slice(0, cap)
  const rest = keys.length - shown.length
  return (
    <ul className="mt-2 space-y-1">
      {shown.map((k) => (
        <li key={k} className="truncate font-mono text-xs text-secondary" title={k}>
          {k}
        </li>
      ))}
      {rest > 0 && <li className="text-xs text-tertiary">and {rest} more…</li>}
    </ul>
  )
}

function DriftPanel({ drift }: { drift: ScanDrift }) {
  return (
    <Card
      title={
        <span className="inline-flex items-center gap-2">
          Drift
          <span className="inline-flex items-center gap-1.5 font-mono text-xs font-normal text-tertiary">
            {shortId(drift.runA.id)}
            <ArrowRight className="size-3.5" aria-hidden />
            {shortId(drift.runB.id)}
          </span>
        </span>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-success-primary/25 bg-success-primary/5 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-success-primary">
            <Plus className="size-4" aria-hidden />
            {drift.added.length} added
          </div>
          <p className="mt-1 text-xs text-tertiary">Finding keys present in B but not A.</p>
          {drift.added.length > 0 && <KeyList keys={drift.added} />}
        </div>
        <div className="rounded-lg border border-error-primary/25 bg-error-primary/5 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-error-primary">
            <Minus className="size-4" aria-hidden />
            {drift.removed.length} removed
          </div>
          <p className="mt-1 text-xs text-tertiary">Finding keys present in A but not B.</p>
          {drift.removed.length > 0 && <KeyList keys={drift.removed} />}
        </div>
        <div className="rounded-lg border border-secondary bg-secondary/30 p-4">
          <div className="text-sm font-semibold text-primary">{drift.unchanged} unchanged</div>
          <p className="mt-1 text-xs text-tertiary">Finding keys present in both runs.</p>
        </div>
      </div>
      <div className="mt-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-tertiary">Why the result changed</h3>
        {drift.explanation.length > 0 ? (
          <ul className="mt-2 space-y-1.5">
            {drift.explanation.map((e) => (
              <li key={e} className="flex items-start gap-2 text-sm text-secondary">
                <ArrowRight className="mt-0.5 size-3.5 shrink-0 text-quaternary" aria-hidden />
                <span className="font-mono text-xs">{e}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-tertiary">
            No manifest deltas were recorded for these runs. Any change in findings then comes from the
            target rather than a reported change in the scanner or its databases.
          </p>
        )}
      </div>
    </Card>
  )
}

export function ScanRunsTab({ engagementId }: { engagementId: string }) {
  const { data, loading, error } = useParallelFetch<[ScanRun[]]>(
    () => Promise.all([api.scanRuns(engagementId)]),
    { deps: [engagementId] },
  )

  const runs = useMemo(() => {
    const list = data?.[0] ?? []
    return [...list].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
  }, [data])

  const [selected, setSelected] = useState<string[]>([])
  const [drift, setDrift] = useState<ScanDrift | null>(null)
  const [comparing, setComparing] = useState(false)
  const [compareErr, setCompareErr] = useState('')

  function toggle(id: string) {
    setDrift(null)
    setCompareErr('')
    setSelected((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id)
      if (prev.length >= 2) return [prev[1], id]
      return [...prev, id]
    })
  }

  async function compare() {
    if (selected.length !== 2) return
    setComparing(true)
    setCompareErr('')
    try {
      setDrift(await api.compareScanRuns(engagementId, selected[0], selected[1]))
    } catch (e) {
      setCompareErr(e instanceof Error ? e.message : 'comparison failed')
    } finally {
      setComparing(false)
    }
  }

  if (loading) return <Spinner label="Loading scan runs…" />
  if (error) return <ErrorState message={error} />
  if (runs.length === 0)
    return (
      <EmptyState
        icon={Package}
        title="No scan runs yet"
        hint="Run an SCA scan to build a reproducibility history and compare results run to run."
      />
    )

  return (
    <div className="space-y-6">
      <Card
        title="Scan runs"
        actions={
          selected.length === 2 ? (
            <Button variant="primary" onClick={compare} disabled={comparing} className="px-3 py-1.5">
              Compare A and B
            </Button>
          ) : (
            <span className="text-xs text-tertiary">Select two runs to compare</span>
          )
        }
      >
        <p className="mb-4 text-sm text-tertiary">
          Every SCA scan seals a manifest of its inputs (tool and database versions, the SBOM hash) and the
          finding keys it produced. Pick two runs to see what changed and why.
        </p>
        <div className="space-y-2">
          {runs.map((r) => {
            const idx = selected.indexOf(r.id)
            return (
              <RunRow
                key={r.id}
                run={r}
                order={idx === -1 ? null : idx + 1}
                selected={idx !== -1}
                disabled={comparing}
                onToggle={() => toggle(r.id)}
              />
            )
          })}
        </div>
      </Card>
      {compareErr && <ErrorState message={compareErr} />}
      {comparing && <Spinner label="Comparing runs…" />}
      {drift && <DriftPanel drift={drift} />}
    </div>
  )
}
