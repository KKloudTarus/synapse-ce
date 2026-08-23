import { useEffect, useState } from 'react'
import { ServerCog } from 'lucide-react'
import { api, ApiError } from '../../lib/api'
import type { FleetAgentDetail, FleetAgentHealth, FleetAgentRow } from '../../lib/types'
import { Button, Card, cn, EmptyState, ErrorState, Pill, Spinner } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { FleetStateBadge, formatFleetTime } from './fleetShared'
import { useFetch } from '../../hooks'

type StateFilter = 'all' | FleetAgentHealth
const FILTERS: { value: StateFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'healthy', label: 'Healthy' },
  { value: 'stale', label: 'Stale' },
  { value: 'revoked', label: 'Revoked' },
]

function AgentDetailCard({ id, onClose }: { id: string; onClose: () => void }) {
  const [detail, setDetail] = useState<FleetAgentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let active = true
    setDetail(null)
    setError(null)
    api
      .getFleetAgent(id)
      .then((d) => {
        if (active) setDetail(d)
      })
      .catch((e) => {
        if (active) setError(e instanceof ApiError ? e.message : 'Failed to load agent')
      })
    return () => {
      active = false
    }
  }, [id, reload])

  return (
    <Card
      className="mt-6"
      title={`Agent ${id}`}
      actions={
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      {error && (
        <div className="space-y-3">
          <ErrorState message={error} />
          <Button variant="secondary" onClick={() => setReload((n) => n + 1)}>
            Retry
          </Button>
        </div>
      )}
      {!detail && !error && <Spinner label="Loading agent…" />}
      {detail && (
        <div>
          <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
            <FleetStateBadge state={detail.agent.state} />
            <span className="text-mutedfg">
              last seen <span className="tabular-nums text-subtlefg">{formatFleetTime(detail.agent.lastSeen)}</span>
            </span>
            {detail.agent.capabilities.map((c) => (
              <Pill key={c}>{c}</Pill>
            ))}
          </div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-subtlefg">Recent work orders</div>
          {detail.recentWork.length === 0 ? (
            <p className="text-sm text-mutedfg">No recent work orders.</p>
          ) : (
            <ul className="divide-y divide-border/60 rounded-lg border border-border">
              {detail.recentWork.map((w) => (
                <li key={w.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 text-sm">
                  <span className="font-mono text-[12px] text-foreground">{w.capability}</span>
                  <span className="font-mono text-[12px] text-mutedfg">{w.assetId}</span>
                  <span className="text-mutedfg">{w.state}</span>
                  <span className="tabular-nums text-subtlefg">{formatFleetTime(w.updatedAt)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  )
}

export function FleetAgents() {
  const [filter, setFilter] = useState<StateFilter>('all')
  const { data: rows, loading, error, refetch } = useFetch(
    () => api.listFleetAgents(filter === 'all' ? undefined : filter),
    { deps: [filter] },
  )
  const [selected, setSelected] = useState<string | null>(null)

  const columns: Column<FleetAgentRow>[] = [
    {
      header: 'Agent',
      className: 'w-44',
      cell: (a) => (
        <button
          type="button"
          onClick={() => setSelected(a.id)}
          title={a.id}
          className="truncate rounded font-mono text-[12px] text-branddim hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg"
        >
          {a.id}
        </button>
      ),
    },
    { header: 'Name', className: 'flex-1', cell: (a) => <span className="text-foreground">{a.name || '—'}</span> },
    { header: 'Platform', className: 'w-28', cell: (a) => <span className="text-mutedfg">{a.platform || '—'}</span> },
    {
      header: 'Version',
      className: 'w-24 tabular-nums',
      cell: (a) => <span className="font-mono text-[12px] text-mutedfg">{a.agentVersion || '—'}</span>,
    },
    { header: 'State', className: 'w-28', cell: (a) => <FleetStateBadge state={a.state} /> },
    {
      header: 'Last seen',
      className: 'w-44 tabular-nums',
      cell: (a) => (
        <span className="text-mutedfg" title={a.lastSeen || undefined}>
          {formatFleetTime(a.lastSeen)}
        </span>
      ),
    },
    {
      header: 'Capabilities',
      className: 'flex-1',
      cell: (a) => <span className="text-mutedfg">{a.capabilities.length ? a.capabilities.join(', ') : '—'}</span>,
    },
    {
      header: 'Work',
      className: 'w-16 tabular-nums text-right',
      cell: (a) => <span className="text-mutedfg">{a.currentWork.toLocaleString()}</span>,
    },
  ]

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-1">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            type="button"
            onClick={() => {
              setSelected(null)
              setFilter(f.value)
            }}
            className={cn(
              'rounded-lg px-3 py-1.5 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
              filter === f.value ? 'bg-brand/10 text-branddim' : 'text-mutedfg hover:bg-elevated hover:text-foreground',
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="space-y-3">
          <ErrorState message={error} />
          <Button variant="secondary" onClick={refetch}>
            Retry
          </Button>
        </div>
      )}
      {loading && <Spinner label="Loading fleet agents…" />}
      {rows && rows.length === 0 && !error && (
        <EmptyState
          icon={ServerCog}
          title="No agents"
          hint={
            filter === 'all'
              ? 'No agents have enrolled for this tenant yet, or the fleet is not enabled.'
              : `No agents are currently ${filter}.`
          }
        />
      )}
      {rows && rows.length > 0 && (
        <Card bodyClass="p-0">
          <VirtualTable
            items={rows}
            columns={columns}
            rowKey={(a) => a.id}
            maxHeightClass="max-h-[60vh]"
            tableMinWidthClass="min-w-[72rem]"
          />
        </Card>
      )}

      {selected && <AgentDetailCard id={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
