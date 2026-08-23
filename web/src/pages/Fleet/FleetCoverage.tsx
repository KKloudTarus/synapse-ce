import { useState } from 'react'
import { ChevronDown, Download01, Shield01 } from '@untitledui/icons'
import { api, ApiError } from '../../lib/api'
import type { FleetAgentHealth, FleetCoverageRow, FleetCoverageSummary, FleetVerdict } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Pill, Spinner, cn } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { FLEET_VERDICT_ORDER, FleetStateBadge, FleetVerdictBadge, formatFleetTime, verdictLabel } from './fleetShared'
import { useFetch, useParallelFetch } from '../../hooks'

// --- Coverage Table Columns ---
const COLUMNS: Column<FleetCoverageRow>[] = [
  {
    header: 'Asset',
    className: 'w-52',
    cell: (r) => (
      <span className="font-mono text-[12px] text-primary" title={r.assetId}>
        {r.assetId}
      </span>
    ),
  },
  {
    header: 'Capability',
    className: 'w-40',
    cell: (r) => (
      <span className="font-mono text-[12px] text-tertiary" title={r.capability || undefined}>
        {r.capability || '—'}
      </span>
    ),
  },
  {
    header: 'Verdict',
    className: 'w-36',
    cell: (r) => <FleetVerdictBadge verdict={r.verdict} />,
  },
  {
    header: 'Detail',
    className: 'flex-1',
    cell: (r) => <span className="text-tertiary">{r.detail || '—'}</span>,
  },
  {
    header: 'Last run',
    className: 'w-44 tabular-nums',
    cell: (r) => (
      <span className="text-tertiary" title={r.lastRun || undefined}>
        {formatFleetTime(r.lastRun)}
      </span>
    ),
  },
  {
    header: 'Agent',
    className: 'w-40',
    cell: (r) => (
      <span className="font-mono text-[12px] text-tertiary" title={r.agentId || undefined}>
        {r.agentId || '—'}
      </span>
    ),
  },
]

// --- Agent Inline Detail ---
const agentDetailCache = new Map<string, any>()

function AgentInlineDetail({ agentId }: { agentId: string }) {
  const cached = agentDetailCache.get(agentId)
  const { data, error, loading } = useFetch(
    () => cached ? Promise.resolve(cached) : api.getFleetAgent(agentId).then(d => { agentDetailCache.set(agentId, d); return d }),
    { deps: [agentId] }
  )
  const detail = data || cached

  if (loading && !detail) return <div className="px-4 py-2"><Spinner className="size-3" /></div>
  if (error && !detail) return <p className="px-4 py-2 text-xs text-critical">{error}</p>
  if (!detail) return null

  return (
    <div className="border-t border-secondary bg-secondary/10 px-4 py-3 space-y-2">
      <div className="flex flex-wrap gap-2">
        {detail.agent.capabilities.map((c: string) => (
          <Pill key={c}>{c}</Pill>
        ))}
      </div>
      {detail.recentWork.length > 0 && (
        <div>
          <div className="text-[11px] font-semibold uppercase text-tertiary mb-1">Recent work</div>
          <div className="grid gap-1">
            {detail.recentWork.slice(0, 5).map((w: any) => (
              <div key={w.id} className="flex items-center gap-3 text-xs text-tertiary">
                <span className="font-mono text-primary font-medium">{w.capability}</span>
                <span className="font-mono">{w.assetId}</span>
                <span>{w.state}</span>
                <span className="ml-auto tabular-nums text-quaternary">{formatFleetTime(w.updatedAt)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// --- Agents Section ---
type StateFilter = 'all' | FleetAgentHealth
const FILTERS: { value: StateFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'healthy', label: 'Healthy' },
  { value: 'stale', label: 'Stale' },
  { value: 'revoked', label: 'Revoked' },
]

export function AgentsSection() {
  const [filter, setFilter] = useState<StateFilter>('all')
  const { data: rows, loading, error, refetch } = useFetch(
    () => api.listFleetAgents(filter === 'all' ? undefined : filter),
    { deps: [filter] },
  )
  const [expandedId, setExpandedId] = useState<string | null>(null)

  return (
    <Card
      title={`Agents${rows ? ` (${rows.length})` : ''}`}
      actions={
        <div className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => { setFilter(f.value); setExpandedId(null) }}
              className={cn(
                'rounded-md px-2 py-1 text-xs font-semibold transition-colors',
                filter === f.value
                  ? 'bg-brand-primary text-brand-secondary'
                  : 'text-tertiary hover:bg-secondary'
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      }
      bodyClass="p-0"
    >
      {loading && <div className="px-4 py-3"><Spinner className="size-4" /></div>}
      {error && (
        <div className="p-4 space-y-3">
          <ErrorState message={error} />
          <Button variant="secondary" onClick={refetch}>Retry</Button>
        </div>
      )}

      {rows && rows.length > 0 && (
        <div className="divide-y divide-secondary">
          {rows.map((agent) => (
            <div key={agent.id}>
              <div
                role="button"
                tabIndex={0}
                onClick={() => setExpandedId(expandedId === agent.id ? null : agent.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    setExpandedId(expandedId === agent.id ? null : agent.id)
                  }
                }}
                className="flex w-full items-center gap-3 px-4 py-2.5 text-sm hover:bg-secondary/30 transition-colors cursor-pointer"
              >
                <span className="font-mono text-xs font-semibold text-primary w-24 truncate">{agent.id}</span>
                <span className="text-secondary flex-1 truncate">{agent.name || '—'}</span>
                <span className="hidden sm:inline text-tertiary text-xs">{agent.platform || '—'}</span>
                <span className="hidden sm:inline font-mono text-xs text-tertiary">{agent.agentVersion || '—'}</span>
                <FleetStateBadge state={agent.state} />
                <span className="text-xs tabular-nums text-quaternary hidden md:inline">{formatFleetTime(agent.lastSeen)}</span>
                <ChevronDown className={cn('size-3.5 text-quaternary transition-transform duration-200', expandedId === agent.id && 'rotate-180')} />
              </div>
              {expandedId === agent.id && <AgentInlineDetail agentId={agent.id} />}
            </div>
          ))}
        </div>
      )}

      {rows && rows.length === 0 && !error && !loading && (
        <p className="px-4 py-3 text-sm text-tertiary">No agents enrolled.</p>
      )}
    </Card>
  )
}

// --- Main Fleet Page ---
export function FleetCoverage() {
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const { data, error, refetch } = useParallelFetch(
    () => Promise.all([api.listFleetCoverage(), api.fleetCoverageSummary()] as const),
    { deps: [] },
  )

  const rows: FleetCoverageRow[] | null = data?.[0] ?? null
  const summary: FleetCoverageSummary | null = data?.[1] ?? null

  async function onExport() {
    setExportError(null)
    setExporting(true)
    try {
      await api.exportFleetCoverage()
    } catch (e) {
      setExportError(e instanceof ApiError ? e.message : 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      {/* Header + inline stats (no card) */}
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Fleet</h1>
        <p className="mt-1 text-sm text-secondary">Agent health and per-asset coverage at a glance</p>

        {summary && (
          <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-secondary bg-secondary/40 px-4 py-2.5">
            <span className="text-sm text-secondary">
              <span className="font-bold text-lg tabular-nums text-primary">{Object.values(summary.rowsByVerdict).reduce((a, b) => a + b, 0)}</span> pairs assessed
            </span>
            <span className="text-secondary">·</span>
            {FLEET_VERDICT_ORDER.filter((v) => (summary.rowsByVerdict[v] ?? 0) > 0).map((v) => (
              <span key={v} className="inline-flex items-center gap-1">
                <FleetVerdictBadge verdict={v as FleetVerdict} />
                <span className="text-xs tabular-nums text-tertiary">{summary.rowsByVerdict[v]}</span>
              </span>
            ))}
            {summary.assetsWithoutAgent > 0 && (
              <>
                <span className="text-secondary">·</span>
                <span className="text-xs text-critical font-medium">{summary.assetsWithoutAgent} without agent</span>
              </>
            )}
          </div>
        )}
      </header>

      {error ? (
        <div className="space-y-3">
          <ErrorState message={error} />
          <Button variant="secondary" onClick={refetch}>Retry</Button>
        </div>
      ) : !rows || !summary ? (
        <Spinner label="Loading fleet coverage…" />
      ) : (
        <div className="space-y-6">
          {/* Agents section */}
          <AgentsSection />

          {/* Per-asset coverage table */}
          {rows.length === 0 ? (
            <EmptyState
              icon={Shield01}
              title="No coverage rows"
              hint="Enrol an agent and register assets to see per-capability coverage."
            />
          ) : (
            <Card
              title="Per-asset coverage"
              bodyClass="p-0"
              actions={
                <Button
                  variant="secondary"
                  onClick={onExport}
                  loading={exporting}
                  className="!border-brand-solid !text-brand-secondary hover:!bg-brand-primary/10"
                >
                  <Download01 className="size-4" /> Export CSV
                </Button>
              }
            >
              {exportError && (
                <div className="px-6 pt-4">
                  <ErrorState message={exportError} />
                </div>
              )}
              <VirtualTable
                items={rows}
                columns={COLUMNS}
                rowKey={(r, i) => `${r.assetId}:${r.capability}:${i}`}
                maxHeightClass="max-h-[65vh]"
                tableMinWidthClass="min-w-[64rem]"
              />
            </Card>
          )}

          <p className="text-xs text-tertiary">
            Every state except <span className="font-semibold text-primary">{verdictLabel('covered')}</span> is a gap — surfaced, not hidden.
          </p>
        </div>
      )}
    </div>
  )
}

export default FleetCoverage
