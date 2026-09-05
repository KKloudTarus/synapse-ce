import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../../lib/api'
import type { Incident, IncidentState } from '../../lib/types'
import { Button, Card, SevBadge, cn } from '../../components/ui'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { OperationalState, TableSkeleton } from '../../components/synapse/OperationalState'
import { Metric, MetricStrip } from '../../components/synapse/Metric'
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
    className: 'w-32',
    cell: (r) => <span className="font-mono text-[12px] text-tertiary" title={r.assetId}>{r.assetId || '—'}</span>,
  },
  {
    header: 'Severity',
    className: 'w-24',
    cell: (r) => <SevBadge sev={r.severity} />,
  },
  {
    header: 'State',
    className: 'w-32',
    cell: (r) => <IncidentStateBadge state={r.state} />,
  },
  {
    header: 'Disposition',
    className: 'w-32',
    cell: (r) => <IncidentDispositionBadge disposition={r.disposition} />,
  },
  {
    header: 'Risk',
    className: 'w-14 text-right',
    cell: riskCell,
  },
  {
    header: 'Opened',
    className: 'w-36 tabular-nums',
    cell: (r) => <span className="text-tertiary" title={r.createdAt}>{formatFleetTime(r.createdAt)}</span>,
  },
  {
    header: 'Updated',
    className: 'w-36 tabular-nums',
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
  // One read of the most recent incidents; the state filter is applied here so the strip and the
  // chip counts describe the whole set while the table shows the selection.
  const { data, loading, error, refetch } = useFetch(() => api.listIncidents({ limit: PAGE_LIMIT }), { deps: [] })

  const all = data?.incidents ?? null
  const rows = all ? (filter === 'all' ? all : all.filter((r) => r.state === filter)) : null
  const strip = summarize(all ?? [])
  const lastUpdate = (all ?? []).reduce<string>((latest, r) => (r.updatedAt > latest ? r.updatedAt : latest), '')

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-5 pb-12">
      <header className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h1 className="text-2xl font-bold tracking-tight text-primary">Incidents</h1>
        {all && (
          <span className="text-xs text-tertiary">
            {all.length
              ? `Last incident update ${formatFleetTime(lastUpdate)}${data?.truncated ? ` · showing the ${PAGE_LIMIT} most recent` : ''}`
              : 'Correlated from runtime detections; none open yet'}
          </span>
        )}
      </header>

      {all && (
        <MetricStrip ariaLabel="Incident summary">
          <Metric label="Open" value={strip.open} tone={strip.open ? 'high' : 'muted'} hint="new, open, reopened" />
          <Metric label="Critical unresolved" value={strip.critical} tone="critical" hint="critical severity, not resolved or closed" />
          <Metric label="In progress" value={strip.inProgress} hint="triaged, investigating, contained, remediated" />
          <Metric label="Resolved" value={strip.resolved} hint="resolved, closed" />
        </MetricStrip>
      )}

      <Card bodyClass="p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-secondary px-4 py-3">
          <div className="flex flex-wrap gap-1" role="group" aria-label="Filter incidents by state">
            {FILTERS.map((f) => {
              const n = f.value === 'all' ? all?.length ?? 0 : strip.byState[f.value] ?? 0
              return (
                <button
                  key={f.value}
                  type="button"
                  aria-pressed={filter === f.value}
                  onClick={() => setFilter(f.value)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-semibold transition-colors',
                    filter === f.value ? 'bg-brand-solid text-primary_on-brand' : 'text-tertiary hover:bg-secondary',
                  )}
                >
                  {f.label}
                  {all && <span className="ml-1 font-mono tabular-nums opacity-70">{n}</span>}
                </button>
              )
            })}
          </div>
          {rows && (
            <span className="ml-auto font-mono text-xs tabular-nums text-quaternary">
              {rows.length === 1 ? '1 incident' : `${rows.length} incidents`}
            </span>
          )}
        </div>

        {error ? (
          <OperationalState
            tone="error"
            title="Could not load incidents"
            detail={error}
            meta={[`observed ${new Date().toISOString()}`]}
            onRetry={refetch}
          />
        ) : loading && !all ? (
          <TableSkeleton rows={6} columns={COLUMNS.length} />
        ) : rows && rows.length > 0 ? (
          <VirtualTable
            items={rows}
            columns={COLUMNS}
            rowKey={(r) => r.id}
            onRowClick={(r) => navigate(`/fleet/incidents/${encodeURIComponent(r.id)}`)}
            rowAriaLabel={(r) => `Open incident ${r.title || r.id}`}
            maxHeightClass="max-h-[70vh]"
            tableMinWidthClass="min-w-[64rem]"
          />
        ) : filter === 'all' ? (
          <OperationalState
            title="No active incidents"
            detail="Detections from enrolled agents are correlated automatically as they arrive; an incident opens here when related detections cross the promotion threshold. Agent health and detection coverage are on the Fleet page."
            action={<Button variant="secondary" onClick={() => navigate('/fleet')}>Open fleet coverage</Button>}
          />
        ) : (
          <OperationalState
            title={`No ${incidentStateLabel(filter as IncidentState).toLowerCase()} incidents`}
            detail="No incident is in this state."
            meta={all && all.length ? [`${all.length} ${all.length === 1 ? 'incident' : 'incidents'} in other states`] : undefined}
            action={<Button variant="secondary" onClick={() => setFilter('all')}>Show all</Button>}
          />
        )}
      </Card>
    </div>
  )
}

const OPEN_STATES: IncidentState[] = ['new', 'open', 'reopened']
const IN_PROGRESS_STATES: IncidentState[] = ['triaged', 'investigating', 'contained', 'remediated']
const RESOLVED_STATES: IncidentState[] = ['resolved', 'closed']

function summarize(incidents: Incident[]) {
  const byState: Partial<Record<IncidentState, number>> = {}
  let open = 0
  let inProgress = 0
  let resolved = 0
  let critical = 0
  for (const inc of incidents) {
    byState[inc.state] = (byState[inc.state] ?? 0) + 1
    if (OPEN_STATES.includes(inc.state)) open++
    else if (IN_PROGRESS_STATES.includes(inc.state)) inProgress++
    else if (RESOLVED_STATES.includes(inc.state)) resolved++
    if (inc.severity === 'critical' && !RESOLVED_STATES.includes(inc.state)) critical++
  }
  return { byState, open, inProgress, resolved, critical }
}

export default Incidents
