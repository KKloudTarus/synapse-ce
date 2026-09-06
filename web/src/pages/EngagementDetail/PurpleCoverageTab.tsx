import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  ShieldTick,
  SlashCircle01,
  Target04,
} from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Pill, Select, Spinner, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useFetch, useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { PurpleCoverageRow, PurpleWorkItem } from '../../lib/api'
import type { TechnicalAsset } from '../../lib/types'

interface RunSummary {
  runId: string
  computedAt: string
  covered: number
  gap: number
  unknown: number
  outOfReach: number
  total: number
  executed: number
  // Coverage is measured over EXECUTED checks only: covered / (covered + gap). It is null when nothing
  // executed (all unknown/out_of_reach), which is "not applicable", not 0%.
  coveragePct: number | null
}

function summarize(rows: PurpleCoverageRow[]): RunSummary[] {
  const byRun = new Map<string, RunSummary>()
  for (const r of rows) {
    let s = byRun.get(r.runId)
    if (!s) {
      s = { runId: r.runId, computedAt: r.computedAt, covered: 0, gap: 0, unknown: 0, outOfReach: 0, total: 0, executed: 0, coveragePct: null }
      byRun.set(r.runId, s)
    }
    s.total += 1
    if (r.computedAt > s.computedAt) s.computedAt = r.computedAt
    if (r.verdict === 'covered') s.covered += 1
    else if (r.verdict === 'gap') s.gap += 1
    else if (r.verdict === 'unknown') s.unknown += 1
    else if (r.verdict === 'out_of_reach') s.outOfReach += 1
  }
  const list = [...byRun.values()]
  for (const s of list) {
    s.executed = s.covered + s.gap
    // floor, never round: 199/200 must read 99%, not a false 100%. Exactly-covered stays 100.
    s.coveragePct = s.executed === 0 ? null : Math.floor((s.covered / s.executed) * 100)
  }
  return list.sort((a, b) => (a.computedAt < b.computedAt ? 1 : -1))
}

function textTone(pct: number | null): string {
  if (pct === null) return 'text-tertiary'
  if (pct >= 80) return 'text-success-primary'
  if (pct >= 50) return 'text-warning-primary'
  return 'text-error-primary'
}

function badgeTone(pct: number | null): string {
  if (pct === null) return 'text-tertiary bg-secondary border-secondary'
  if (pct >= 80) return 'text-success-primary bg-success-primary/10 border-success-primary/25'
  if (pct >= 50) return 'text-warning-primary bg-warning-primary/10 border-warning-primary/25'
  return 'text-error-primary bg-error-primary/10 border-error-primary/25'
}

function pctLabel(pct: number | null): string {
  return pct === null ? 'N/A' : `${pct}%`
}

function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 8)}…` : id
}

function formatWhen(iso: string): string {
  if (!iso) return 'unknown time'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function VerdictCount({
  icon: Icon,
  count,
  label,
  tone,
}: {
  icon: typeof CheckCircle
  count: number
  label: string
  tone: string
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon className={cn('size-4 shrink-0', tone)} aria-hidden />
      <span className="text-sm font-semibold text-primary">{count}</span>
      <span className="text-xs text-tertiary">{label}</span>
    </div>
  )
}

function SummaryCard({ latest }: { latest: RunSummary }) {
  return (
    <Card title="Detection coverage" titleClassName="flex items-center gap-2">
      <div className="flex flex-wrap items-center gap-x-8 gap-y-4">
        <div className="flex items-baseline gap-2">
          <span className={cn('text-4xl font-bold tabular-nums', textTone(latest.coveragePct))}>
            {pctLabel(latest.coveragePct)}
          </span>
          <span className="text-sm text-tertiary">
            {latest.executed > 0
              ? `of ${latest.executed} executed check${latest.executed === 1 ? '' : 's'} detected`
              : 'no checks executed this run'}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-x-6 gap-y-2">
          <VerdictCount icon={CheckCircle} count={latest.covered} label="covered" tone="text-success-primary" />
          <VerdictCount icon={AlertTriangle} count={latest.gap} label="gaps" tone="text-error-primary" />
          <VerdictCount icon={HelpCircle} count={latest.unknown} label="not run" tone="text-quaternary" />
          <VerdictCount icon={SlashCircle01} count={latest.outOfReach} label="out of reach" tone="text-quaternary" />
        </div>
      </div>
      <p className="mt-4 text-xs text-tertiary">
        Coverage is measured over executed checks only (one per attack technique per asset). A gap is a
        check that ran without its expected detection firing; it becomes a work item below. Checks that did
        not run or cannot be emulated are shown but excluded from the percentage.
      </p>
    </Card>
  )
}

function RunRow({
  run,
  selected,
  disabled,
  onSelect,
}: {
  run: RunSummary
  selected: boolean
  disabled: boolean
  onSelect: () => void
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={disabled}
      aria-current={selected}
      aria-label={`Emulation run ${shortId(run.runId)}, ${pctLabel(run.coveragePct)} coverage`}
      className={cn(
        'flex w-full flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border px-4 py-3 text-left transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand disabled:cursor-not-allowed disabled:opacity-60',
        selected
          ? 'border-brand-solid bg-brand-primary/5 ring-1 ring-inset ring-brand/25'
          : 'border-secondary bg-primary hover:bg-secondary/40',
      )}
    >
      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-secondary">
        <Target04 className="size-3.5 text-quaternary" aria-hidden />
        {shortId(run.runId)}
      </span>
      <span className="text-xs text-tertiary">{formatWhen(run.computedAt)}</span>
      <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-xs font-bold', badgeTone(run.coveragePct))}>
        {pctLabel(run.coveragePct)}
      </span>
      <span className="ml-auto flex flex-wrap items-center gap-1.5 text-xs">
        <Pill className="text-success-primary">{run.covered} covered</Pill>
        {run.gap > 0 && <Pill className="text-error-primary">{run.gap} gaps</Pill>}
        {run.unknown > 0 && <Pill>{run.unknown} not run</Pill>}
      </span>
    </button>
  )
}

function GapList({ items, loading, error }: { items: PurpleWorkItem[]; loading: boolean; error: string }) {
  return (
    <Card title="Detection gaps to close" titleClassName="flex items-center gap-2">
      {loading ? (
        <Spinner label="Loading gaps…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : items.length === 0 ? (
        <div className="flex items-center gap-2 text-sm text-tertiary">
          <CheckCircle className="size-4 text-success-primary" aria-hidden />
          No detection gaps recorded for this run.
        </div>
      ) : (
        <ul className="space-y-2">
          {items.map((w) => (
            <li
              key={`${w.techniqueId}:${w.missingDetection}`}
              className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-secondary bg-secondary/20 px-3 py-2"
            >
              <AlertTriangle className="size-4 shrink-0 text-error-primary" aria-hidden />
              <span className="font-mono text-sm font-semibold text-primary">{w.techniqueId}</span>
              {w.taxonomyRef && <Pill className="font-mono">{w.taxonomyRef}</Pill>}
              <span className="text-xs text-tertiary">
                write detection{w.missingDetection ? `: ${w.missingDetection}` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

// RunEmulationControl triggers a governed adversary-emulation run against a chosen asset and refreshes the
// coverage once it completes. The run is admitted per technique through the engagement's rules of
// engagement, so a technique the RoE does not permit is recorded as a gap rather than executed.
function RunEmulationControl({ engagementId, onRan }: { engagementId: string; onRan: () => void }) {
  const { data: assets } = useFetch<TechnicalAsset[]>(() => api.listTechnicalAssets(), { deps: [] })
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const { notify } = useToast()

  const options = useMemo(
    () => [
      { value: '', label: assets && assets.length > 0 ? 'Select a target asset…' : 'No assets enrolled' },
      ...(assets ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.kind})` })),
    ],
    [assets],
  )

  async function run() {
    if (!target) return
    setBusy(true)
    setErr('')
    try {
      const res = await api.runEmulation(engagementId, target)
      // A toast, not local state: the parent shows a page-level spinner while coverage refetches, which
      // unmounts this control, so an inline message would be discarded.
      notify(`Emulation complete: ${res.executed} of ${res.techniques} techniques executed.`, 'success')
      onRan()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to run emulation')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Run adversary emulation"
      actions={
        <Button loading={busy} disabled={!target} onClick={run} variant="primary" className="px-3 py-1.5">
          <ShieldTick className="size-4" /> Run emulation
        </Button>
      }
    >
      <div className="flex flex-wrap items-end gap-x-8 gap-y-4">
        <div className="space-y-1.5">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Target asset</div>
          <Select value={target} onValueChange={setTarget} size="sm" aria-label="Target asset" className="w-80" options={options} />
        </div>
      </div>
      <p className="mt-3 text-xs text-tertiary">
        Runs the ATT&CK technique catalogue against the asset under this engagement's rules of engagement,
        then joins each expected detection against what actually fired. A technique the rules of engagement
        do not permit is recorded as not executed, never run.
      </p>
      {!target && <p className="mt-1 text-xs text-quaternary">Select a target asset to enable the run.</p>}
      {err && <p className="mt-2 text-xs text-error-primary">{err}</p>}
    </Card>
  )
}

export function PurpleCoverageTab({ engagementId }: { engagementId: string }) {
  const [refreshKey, setRefreshKey] = useState(0)
  const { data, loading, error } = useParallelFetch<[PurpleCoverageRow[]]>(
    () => Promise.all([api.purpleCoverage(engagementId)]),
    { deps: [engagementId, refreshKey] },
  )

  const runs = useMemo(() => summarize(data?.[0] ?? []), [data])
  const [selectedRun, setSelectedRun] = useState<string | null>(null)
  const [items, setItems] = useState<PurpleWorkItem[]>([])
  const [itemsLoading, setItemsLoading] = useState(false)
  const [itemsErr, setItemsErr] = useState('')

  // Default to the most recent run, and never point at a run that is no longer in the list.
  const activeRun = (selectedRun && runs.some((r) => r.runId === selectedRun) ? selectedRun : runs[0]?.runId) ?? null

  useEffect(() => {
    if (!activeRun) return
    let alive = true
    setItemsLoading(true)
    setItemsErr('')
    api
      .purpleWorkItems(engagementId, activeRun)
      .then((w) => {
        if (alive) setItems(w)
      })
      .catch((e) => {
        if (alive) setItemsErr(e instanceof Error ? e.message : 'failed to load gaps')
      })
      .finally(() => {
        if (alive) setItemsLoading(false)
      })
    return () => {
      alive = false
    }
  }, [engagementId, activeRun])

  if (loading) return <Spinner label="Loading purple coverage…" />
  if (error) return <ErrorState message={error} />
  if (runs.length === 0)
    return (
      <div className="space-y-6">
        <RunEmulationControl engagementId={engagementId} onRan={() => setRefreshKey((k) => k + 1)} />
        <EmptyState
          icon={ShieldTick}
          title="No purple-team coverage yet"
          hint="Run an adversary emulation on an enrolled asset; coverage joins each executed technique with the detections that fired."
        />
      </div>
    )

  return (
    <div className="space-y-6">
      <RunEmulationControl engagementId={engagementId} onRan={() => setRefreshKey((k) => k + 1)} />
      <SummaryCard latest={runs[0]} />
      {runs.length > 1 && (
        <Card title="Coverage by emulation run">
          <div className="space-y-2" role="group" aria-label="Emulation runs">
            {runs.map((r) => (
              <RunRow
                key={r.runId}
                run={r}
                selected={r.runId === activeRun}
                disabled={itemsLoading}
                onSelect={() => setSelectedRun(r.runId)}
              />
            ))}
          </div>
        </Card>
      )}
      <GapList items={items} loading={itemsLoading} error={itemsErr} />
    </div>
  )
}
