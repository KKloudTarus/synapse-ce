import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { Incident, IncidentState } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, SevBadge, Spinner, cn } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import { IncidentDispositionBadge, IncidentStateBadge, INCIDENT_STATE_OPTIONS, incidentStateLabel } from './incidentShared'

const PAGE_LIMIT = 200

type StateFilter = 'all' | IncidentState

function riskCell(inc: Incident) {
  if (!inc.risk) return <span className="text-quaternary">—</span>
  const r = inc.risk.risk
  const tone = r >= 75 ? 'text-critical' : r >= 50 ? 'text-high' : r >= 25 ? 'text-medium' : 'text-tertiary'
  return (
    <span className={cn('font-mono text-sm font-semibold tabular-nums', tone)} title={`Confidence ${inc.risk.confidence} · Coverage ${inc.risk.coverage}`}>
      {r}
    </span>
  )
}

const COLUMNS: Column<Incident>[] = [
  {
    header: 'Title',
    className: 'flex-1 min-w-0',
    cell: (r) => (
      <div className="min-w-0">
        <div className="truncate text-primary" title={r.title}>{r.title || r.id}</div>
        <div className="truncate font-mono text-[11px] text-quaternary" title={r.id}>{r.id}</div>
      </div>
    ),
  },
  {
    header: 'Asset',
    className: 'w-40',
    cell: (r) => <span className="font-mono text-[12px] text-tertiary" title={r.assetId}>{r.assetId || '—'}</span>,
  },
  {
    header: 'Severity',
    className: 'w-28',
    cell: (r) => <SevBadge sev={r.severity} />,
  },
  {
    header: 'State',
    className: 'w-36',
    cell: (r) => <IncidentStateBadge state={r.state} />,
  },
  {
    header: 'Disposition',
    className: 'w-40',
    cell: (r) => <IncidentDispositionBadge disposition={r.disposition} />,
  },
  {
    header: 'Risk',
    className: 'w-20 text-right',
    cell: riskCell,
  },
  {
    header: 'Updated',
    className: 'w-44 tabular-nums',
    cell: (r) => <span className="text-tertiary" title={r.updatedAt}>{formatFleetTime(r.updatedAt)}</span>,
  },
]

const FILTERS: { value: StateFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  ...INCIDENT_STATE_OPTIONS.map((s) => ({ value: s, label: incidentStateLabel(s) })),
]

export function Incidents() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState<StateFilter>('all')
  const { data, loading, error, refetch } = useFetch(
    () => api.listIncidents({ state: filter === 'all' ? undefined : filter, limit: PAGE_LIMIT }),
    { deps: [filter] },
  )

  const rows = data?.incidents ?? null

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Incidents</h1>
        <p className="mt-1 text-sm text-tertiary">
          Correlated runtime detections, tri-scored (Risk · Confidence · Coverage) and dispositioned by an analyst.
        </p>
      </header>

      {error ? (
        <div className="space-y-3">
          <ErrorState message={error} />
          <Button variant="secondary" onClick={refetch}>Retry</Button>
        </div>
      ) : (
        <Card
          title={`Incidents${rows ? ` (${rows.length}${data?.truncated ? '+' : ''})` : ''}`}
          bodyClass="p-0"
          actions={
            <div className="flex flex-wrap gap-1">
              {FILTERS.map((f) => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setFilter(f.value)}
                  className={cn(
                    'rounded-md px-2 py-1 text-xs font-semibold transition-colors',
                    filter === f.value ? 'bg-brand-solid text-primary_on-brand' : 'text-tertiary hover:bg-secondary',
                  )}
                >
                  {f.label}
                </button>
              ))}
            </div>
          }
        >
          {loading && !rows ? (
            <div className="px-4 py-6"><Spinner label="Loading incidents…" /></div>
          ) : rows && rows.length > 0 ? (
            <VirtualTable
              items={rows}
              columns={COLUMNS}
              rowKey={(r) => r.id}
              onRowClick={(r) => navigate(`/fleet/incidents/${encodeURIComponent(r.id)}`)}
              rowAriaLabel={(r) => `Open incident ${r.title || r.id}`}
              maxHeightClass="max-h-[70vh]"
              tableMinWidthClass="min-w-[72rem]"
            />
          ) : (
            <div className="p-6">
              <EmptyState
                icon={AlertTriangle}
                title={filter === 'all' ? 'No incidents' : `No ${incidentStateLabel(filter as IncidentState).toLowerCase()} incidents`}
                hint="Incidents appear once runtime detections are correlated for an engagement."
              />
            </div>
          )}
        </Card>
      )}
    </div>
  )
}

export default Incidents
