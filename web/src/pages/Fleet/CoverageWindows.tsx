import { useState } from 'react'
import { AlertTriangle, SearchLg, Signal01 } from '@untitledui/icons'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { CoverageVector, CoverageWindow } from '../../lib/api'

const CLASSES: { key: keyof Pick<CoverageVector, 'process' | 'network' | 'file' | 'privilege'>; label: string }[] = [
  { key: 'process', label: 'Process' },
  { key: 'network', label: 'Network' },
  { key: 'file', label: 'File' },
  { key: 'privilege', label: 'Privilege' },
]

function shortId(id: string): string {
  if (!id) return '—'
  return id.length > 12 ? `${id.slice(0, 10)}…` : id
}

function formatWhen(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function stateTone(state: string): string {
  const s = state.toLowerCase()
  if (s.includes('covered') || s.includes('healthy') || s.includes('active')) return 'text-success-primary bg-success-primary/10 ring-success-primary/25'
  if (s.includes('degrad') || s.includes('partial') || s.includes('stale')) return 'text-warning-primary bg-warning-primary/10 ring-warning-primary/25'
  if (s.includes('blind') || s.includes('gap') || s.includes('lost') || s.includes('none')) return 'text-error-primary bg-error-primary/10 ring-error-primary/25'
  return 'text-tertiary bg-secondary ring-secondary'
}

function CoverageDot({ label, value }: { label: string; value: number }) {
  const covered = value > 0
  return (
    <div className="flex items-center gap-1.5" title={`${label}: ${covered ? 'covered' : 'no coverage'}`}>
      <span className={cn('size-2.5 rounded-full', covered ? 'bg-success-primary' : 'bg-error-primary/70')} aria-hidden />
      <span className={cn('text-xs', covered ? 'font-medium text-secondary' : 'text-quaternary')}>{label}</span>
    </div>
  )
}

function Stat({ label, value, warn }: { label: string; value: number; warn?: boolean }) {
  return (
    <div className="flex flex-col">
      <span className={cn('text-sm font-semibold tabular-nums', warn && value > 0 ? 'text-error-primary' : 'text-primary')}>{value}</span>
      <span className="text-[11px] uppercase tracking-wide text-quaternary">{label}</span>
    </div>
  )
}

function WindowCard({ w }: { w: CoverageWindow }) {
  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-primary">{shortId(w.assetId)}</span>
            {w.revision && <Pill className="font-mono">{shortId(w.revision)}</Pill>}
            {w.gapCount > 0 && (
              <Pill className="bg-error-primary/10 text-error-primary ring-1 ring-inset ring-error-primary/25">
                <AlertTriangle className="mr-1 inline size-3" /> {w.gapCount} gap{w.gapCount === 1 ? '' : 's'}
              </Pill>
            )}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-tertiary">
            <span>agent <span className="font-mono text-secondary">{shortId(w.agentId)}</span></span>
            <span>host <span className="font-mono text-secondary">{shortId(w.hostId)}</span></span>
          </div>
          <div className="text-xs text-quaternary">
            {formatWhen(w.since)} → {formatWhen(w.until)} · sealed {formatWhen(w.createdAt)}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          {CLASSES.map((c) => (
            <CoverageDot key={c.key} label={c.label} value={w.coverage[c.key]} />
          ))}
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-8 gap-y-3 border-t border-secondary pt-3">
        <Stat label="Sampled" value={w.sampledCount} />
        <Stat label="Batches" value={w.batchCount} />
        <Stat label="Truncated" value={w.truncatedCount} warn />
        <Stat label="Dropped" value={w.droppedCount} warn />
        <Stat label="Gaps" value={w.gapCount} warn />
      </div>

      {w.states.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {w.states.map((s, i) => (
            <span
              key={`${s.class}-${i}`}
              className={cn('inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs ring-1 ring-inset', stateTone(s.state))}
              title={s.reason || undefined}
            >
              <span className="font-medium capitalize">{s.class}</span>
              <span className="opacity-80">{s.state}</span>
            </span>
          ))}
        </div>
      )}

      {w.coverage.reasons.length > 0 && (
        <p className="mt-2 text-xs text-tertiary">{w.coverage.reasons.join(' · ')}</p>
      )}
      {w.inputDigest && (
        <p className="mt-2 font-mono text-[11px] text-quaternary">input {shortId(w.inputDigest)}</p>
      )}
    </Card>
  )
}

export function CoverageWindows() {
  const [asset, setAsset] = useState('')
  const [agent, setAgent] = useState('')
  const [applied, setApplied] = useState<{ assetId?: string; agentId?: string }>({})

  const { data, loading, error } = useFetch(() => api.listCoverageWindows({ ...applied, limit: 100 }), {
    deps: [applied.assetId, applied.agentId],
  })

  const windows = data ?? []

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-primary sm:text-display-xs">
          <Signal01 className="size-6 text-brand-secondary" aria-hidden /> Coverage windows
        </h1>
        <p className="mt-1 text-sm text-secondary">
          Immutable telemetry-coverage revisions per asset. Each window seals the per-class sensor state and
          the sample, drop, and gap counts it was computed from, so coverage over time is auditable.
        </p>
      </header>

      <Card title="Filters">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-56 flex-1">
            <Field label="Asset id">
              <Input value={asset} onChange={(e) => setAsset(e.target.value)} placeholder="asset id" className="font-mono" aria-label="Filter by asset id" />
            </Field>
          </div>
          <div className="min-w-56 flex-1">
            <Field label="Agent id">
              <Input value={agent} onChange={(e) => setAgent(e.target.value)} placeholder="agent id" className="font-mono" aria-label="Filter by agent id" />
            </Field>
          </div>
          <Button
            variant="secondary-color"
            className="px-3 py-2"
            onClick={() => setApplied({ assetId: asset.trim() || undefined, agentId: agent.trim() || undefined })}
          >
            <SearchLg className="size-4" /> Apply
          </Button>
        </div>
      </Card>

      {loading ? (
        <Spinner label="Loading coverage windows…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : windows.length === 0 ? (
        <EmptyState
          icon={Signal01}
          title="No coverage windows"
          hint="A window is sealed when the fleet reconciles an agent's telemetry into a coverage revision. None match this filter yet."
        />
      ) : (
        <div className="space-y-3">
          {windows.map((w) => (
            <WindowCard key={`${w.assetId}-${w.revision}-${w.createdAt}`} w={w} />
          ))}
        </div>
      )}
    </div>
  )
}

export default CoverageWindows
