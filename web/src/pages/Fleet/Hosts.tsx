import { useNavigate } from 'react-router-dom'
import { Server02 } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { HostRow } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Spinner, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabledMessage } from '../../components/synapse/FeatureDisabledState'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import { HostScanBadge, SeverityCount, hostDegraded, hostOS } from './hostShared'

const COLUMNS: Column<HostRow>[] = [
  {
    header: 'Host',
    className: 'flex-1 min-w-0',
    cell: (r) => (
      <div className="min-w-0">
        <div className="truncate text-primary" title={r.asset.name}>{r.asset.name || r.asset.key}</div>
        <div className="truncate font-mono text-[11px] text-quaternary" title={r.asset.key}>{r.asset.key}</div>
      </div>
    ),
  },
  {
    header: 'OS',
    className: 'w-40',
    cell: (r) => <span className="truncate text-secondary" title={hostOS(r)}>{hostOS(r)}</span>,
  },
  {
    header: 'Packages',
    className: 'w-24 text-right',
    cell: (r) => (
      <span className={cn('font-mono text-sm tabular-nums', r.packages ? 'text-secondary' : 'text-quaternary')} title={hostDegraded(r) ? 'A package database on this host could not be read; the list is incomplete.' : undefined}>
        {r.packages || (r.asset.attributes.packages ?? '0')}{hostDegraded(r) ? '*' : ''}
      </span>
    ),
  },
  { header: 'Critical', className: 'w-20 text-right', cell: (r) => <SeverityCount count={r.summary.critical} tone="critical" /> },
  { header: 'High', className: 'w-20 text-right', cell: (r) => <SeverityCount count={r.summary.high} tone="high" /> },
  { header: 'Medium', className: 'w-20 text-right', cell: (r) => <SeverityCount count={r.summary.medium} tone="medium" /> },
  { header: 'Low', className: 'w-20 text-right', cell: (r) => <SeverityCount count={r.summary.low} tone="low" /> },
  {
    header: 'Fixable',
    className: 'w-20 text-right',
    cell: (r) => <span className={cn('font-mono text-sm tabular-nums', r.summary.fixable ? 'text-secondary' : 'text-quaternary')}>{r.summary.fixable}</span>,
  },
  {
    header: 'KEV',
    className: 'w-16 text-right',
    cell: (r) => <span className={cn('font-mono text-sm tabular-nums', r.summary.kev ? 'font-semibold text-critical' : 'text-quaternary')}>{r.summary.kev}</span>,
  },
  { header: 'Scan', className: 'w-40', cell: (r) => <HostScanBadge row={r} /> },
  {
    header: 'Recorded',
    className: 'w-44 tabular-nums',
    cell: (r) => <span className="text-tertiary" title={r.recordedAt ?? undefined}>{formatFleetTime(r.recordedAt ?? '')}</span>,
  },
]

export function Hosts() {
  const navigate = useNavigate()
  const { data: rows, loading, error, refetch } = useFetch<HostRow[]>(() => api.listHosts(), { deps: [] })

  if (error && isFeatureDisabledMessage(error)) {
    return (
      <FeatureDisabledState
        feature="Fleet host inventory"
        envVar="SYNAPSE_FLEET_HOST_INGEST_ENABLED"
        hint="Host vulnerabilities need the fleet asset model and host inventory ingest. Enrol a synapse-agent once they are on."
      />
    )
  }

  const scanned = rows?.filter((r) => r.engagementId).length ?? 0
  const totals = (rows ?? []).reduce(
    (acc, r) => ({ critical: acc.critical + r.summary.critical, high: acc.high + r.summary.high, kev: acc.kev + r.summary.kev }),
    { critical: 0, high: 0, kev: 0 },
  )

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Hosts</h1>
          <p className="mt-1 max-w-2xl text-sm text-tertiary">
            Every host a fleet agent inventories. Installed OS packages are correlated with advisories on each sync; the counts are open findings, worst host first.
          </p>
        </div>
        {rows && rows.length > 0 && (
          <dl className="flex gap-6 text-sm">
            <div><dt className="text-xs uppercase tracking-wide text-quaternary">Hosts</dt><dd className="font-mono tabular-nums text-primary">{rows.length}<span className="text-quaternary"> · {scanned} scanned</span></dd></div>
            <div><dt className="text-xs uppercase tracking-wide text-quaternary">Critical</dt><dd className={cn('font-mono tabular-nums', totals.critical ? 'text-critical' : 'text-quaternary')}>{totals.critical}</dd></div>
            <div><dt className="text-xs uppercase tracking-wide text-quaternary">High</dt><dd className={cn('font-mono tabular-nums', totals.high ? 'text-high' : 'text-quaternary')}>{totals.high}</dd></div>
            <div><dt className="text-xs uppercase tracking-wide text-quaternary">KEV</dt><dd className={cn('font-mono tabular-nums', totals.kev ? 'text-critical' : 'text-quaternary')}>{totals.kev}</dd></div>
          </dl>
        )}
      </header>

      {error ? (
        <div className="space-y-3">
          <ErrorState message={error} />
          <Button variant="secondary" onClick={refetch}>Retry</Button>
        </div>
      ) : (
        <Card title={`Hosts${rows ? ` (${rows.length})` : ''}`} bodyClass="p-0">
          {loading && !rows ? (
            <div className="px-4 py-6"><Spinner label="Loading hosts…" /></div>
          ) : rows && rows.length > 0 ? (
            <VirtualTable
              items={rows}
              columns={COLUMNS}
              rowKey={(r) => r.asset.id}
              onRowClick={(r) => navigate(`/fleet/hosts/${encodeURIComponent(r.asset.id)}`)}
              rowAriaLabel={(r) => `Open host ${r.asset.name || r.asset.key}`}
              maxHeightClass="max-h-[70vh]"
              tableMinWidthClass="min-w-[80rem]"
            />
          ) : (
            <div className="p-6">
              <EmptyState
                icon={Server02}
                title="No hosts inventoried"
                hint="A host appears after an enrolled synapse-agent posts its first inventory. Packages it reports are scanned on the same sync."
              />
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
