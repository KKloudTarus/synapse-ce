import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Play,
  ShieldTick,
  SlashCircle01,
  Target04,
} from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Spinner, cn } from '../../components/ui'
import { useToast } from '../../components/synapse/Toast'
import { useParallelFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { EmulationRunSummary, PurpleCoverageRow, PurpleWorkItem } from '../../lib/api'
import type { Engagement } from '../../lib/types'

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

// windowOpen reports whether now sits inside the engagement's authorization window. An unset bound is
// open on that side. It mirrors the server gate so the run action can explain a closed window before the
// request 403s.
function windowOpen(eng: Engagement | undefined): boolean {
  if (!eng) return true
  const now = Date.now()
  if (eng.authorizedFrom) {
    const f = new Date(eng.authorizedFrom).getTime()
    if (!Number.isNaN(f) && now < f) return false
  }
  if (eng.authorizedTo) {
    const t = new Date(eng.authorizedTo).getTime()
    if (!Number.isNaN(t) && now > t) return false
  }
  return true
}

function RunEmulationPanel({
  engagementId,
  eng,
  onRan,
}: {
  engagementId: string
  eng: Engagement | undefined
  onRan: (runId: string) => void
}) {
  // Default to the first in-scope target: the run target must be within engagement scope (the server
  // refuses an out-of-scope target), and coverage joins against detections keyed by that asset value.
  const [target, setTarget] = useState(eng?.inScope[0]?.value ?? '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [last, setLast] = useState<EmulationRunSummary | null>(null)
  const { notify } = useToast()

  const roeComplete = eng?.roe.offensive?.complete ?? false
  const inWindow = windowOpen(eng)
  const gated = !roeComplete || !inWindow
  const canRun = target.trim() !== '' && !busy && !gated

  async function run() {
    setBusy(true)
    setErr('')
    try {
      const summary = await api.runEmulation(engagementId, target.trim())
      setLast(summary)
      notify(
        `Emulation run complete: ${summary.executed}/${summary.techniques} executed, ${summary.gaps} gap${summary.gaps === 1 ? '' : 's'}.`,
        'success',
      )
      onRan(summary.runId)
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to run emulation'
      setErr(message)
      notify(message, 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Run adversary emulation" titleClassName="flex items-center gap-2">
      <p className="text-xs text-tertiary">
        Runs each catalogued technique through the offensive governance gate and joins it against the
        detections on the target asset. An authorized-but-undetected technique is a coverage gap.
      </p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <div className="min-w-64 flex-1">
          <Field label="Target asset" hint="Coverage is per-asset">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="in-scope asset"
              className="font-mono"
              aria-label="Emulation target asset id"
            />
          </Field>
        </div>
        <div className="flex flex-col items-end gap-1">
          <Button loading={busy} disabled={!canRun} onClick={run} variant="primary" className="px-3 py-2">
            <Play className="size-4" /> Run emulation
          </Button>
          {gated && (
            <span className="inline-flex items-center gap-1 text-[11px] text-medium">
              <AlertTriangle className="size-3 shrink-0" aria-hidden />
              {!roeComplete ? 'Offensive RoE incomplete' : 'Outside authorization window'}
            </span>
          )}
        </div>
      </div>
      {gated && (
        <p className="mt-2 text-[11px] text-tertiary">
          {!roeComplete
            ? 'Complete the offensive rules of engagement under Settings before a run can be authorized.'
            : 'A run is refused until the engagement is inside its authorization window.'}
        </p>
      )}
      {last && !err && (
        <p className="mt-3 text-xs text-tertiary">
          Latest run <span className="font-mono text-secondary">{shortId(last.runId)}</span>:{' '}
          <span className="font-semibold text-primary">{last.executed}</span> executed,{' '}
          <span className="font-semibold text-error-primary">{last.gaps}</span> gap{last.gaps === 1 ? '' : 's'},{' '}
          <span className="font-semibold text-success-primary">{last.covered}</span> covered.
        </p>
      )}
      {err && (
        <div className="mt-3">
          <ErrorState message={err} />
        </div>
      )}
    </Card>
  )
}

export function PurpleCoverageTab({ engagementId, eng }: { engagementId: string; eng?: Engagement }) {
  const { data, loading, error, refetch } = useParallelFetch<[PurpleCoverageRow[]]>(
    () => Promise.all([api.purpleCoverage(engagementId)]),
    { deps: [engagementId] },
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

  // After a run, reload coverage and point at the new run once it lands in the reloaded list.
  const onRan = (runId: string) => {
    setSelectedRun(runId)
    refetch()
  }

  if (loading) return <Spinner label="Loading purple coverage…" />
  if (error) return <ErrorState message={error} />
  if (runs.length === 0)
    return (
      <div className="space-y-6">
        <RunEmulationPanel engagementId={engagementId} eng={eng} onRan={onRan} />
        <EmptyState
          icon={ShieldTick}
          title="No purple-team coverage yet"
          hint="Run an adversary emulation on the target asset above; coverage joins each executed technique with the detections that fired."
        />
      </div>
    )

  return (
    <div className="space-y-6">
      <RunEmulationPanel engagementId={engagementId} eng={eng} onRan={onRan} />
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
