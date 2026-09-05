import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { SearchSm } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { HostRow } from '../../lib/types'
import { Button, Card, Input, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabledMessage } from '../../components/synapse/FeatureDisabledState'
import { Metric, MetricStrip } from '../../components/synapse/Metric'
import { OperationalState, TableSkeleton } from '../../components/synapse/OperationalState'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import { HostScanBadge, SeverityCount, hostDegraded, hostOS, hostScanState, hostShortName, reportedPackages, type HostScanState } from './hostShared'

type StateFilter = 'all' | 'vulnerable' | 'critical' | 'no-inventory' | 'attention'

const FILTERS: { value: StateFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'vulnerable', label: 'With findings' },
  { value: 'critical', label: 'Critical or high' },
  { value: 'attention', label: 'Needs attention' },
  { value: 'no-inventory', label: 'No inventory' },
]

const ATTENTION: HostScanState[] = ['none', 'unrecorded', 'failed']

function matchesFilter(r: HostRow, f: StateFilter): boolean {
  const state = hostScanState(r)
  switch (f) {
    case 'vulnerable': return r.summary.total > 0
    case 'critical': return r.summary.critical + r.summary.high > 0
    case 'no-inventory': return state === 'none' || state === 'unrecorded'
    case 'attention': return ATTENTION.includes(state) || hostDegraded(r)
    default: return true
  }
}

function matchesSearch(r: HostRow, q: string): boolean {
  if (!q) return true
  const hay = [r.asset.name, r.asset.key, r.asset.attributes.machine_id, r.asset.attributes.reporting_agent_id, r.asset.attributes.os, r.asset.attributes.os_version, r.asset.attributes.cloud_instance]
    .filter(Boolean).join(' ').toLowerCase()
  return hay.includes(q)
}

const COLUMNS: Column<HostRow>[] = [
  {
    header: 'Host',
    className: 'flex-1 min-w-[10rem]',
    cell: (r) => (
      <div className="min-w-0">
        <div className="truncate font-medium text-primary" title={r.asset.name}>{hostShortName(r.asset.name, r.asset.key)}</div>
        <div className="truncate font-mono text-[11px] text-quaternary" title={r.asset.key}>{r.asset.key}</div>
      </div>
    ),
  },
  {
    header: 'OS / arch',
    className: 'w-28',
    cell: (r) => (
      <div className="min-w-0 truncate text-secondary" title={`${hostOS(r)} ${r.asset.attributes.arch ?? ''}`}>
        {hostOS(r)}{r.asset.attributes.arch ? <span className="text-quaternary"> · {r.asset.attributes.arch}</span> : null}
      </div>
    ),
  },
  {
    header: 'Packages',
    className: 'w-20 text-right',
    cell: (r) => {
      const n = reportedPackages(r)
      const degraded = hostDegraded(r)
      return (
        <span
          className={cn('font-mono text-sm tabular-nums', n ? 'text-secondary' : 'text-quaternary')}
          title={degraded ? 'A package database on this host could not be read; the list is incomplete.' : r.packages ? 'Recorded and scanned' : n ? 'Reported by the agent, not recorded' : 'The agent sent no package list'}
        >
          {n ? n.toLocaleString() : 'none'}{degraded ? <span className="text-warning-primary"> ·incomplete</span> : null}
        </span>
      )
    },
  },
  {
    header: 'Open findings',
    className: 'w-52',
    cell: (r) => (
      <div className="flex items-baseline gap-3 tabular-nums" title={`${r.summary.critical} critical, ${r.summary.high} high, ${r.summary.medium} medium, ${r.summary.low} low`}>
        {(['critical', 'high', 'medium', 'low'] as const).map((tone) => (
          <span key={tone} className="flex items-baseline gap-1">
            <SeverityCount count={r.summary[tone]} tone={tone} />
            <span className="text-[10px] uppercase text-quaternary">{tone === 'critical' ? 'crit' : tone === 'medium' ? 'med' : tone}</span>
          </span>
        ))}
      </div>
    ),
  },
  {
    header: 'Fixable',
    className: 'w-16 text-right',
    cell: (r) => <span className={cn('font-mono text-sm tabular-nums', r.summary.fixable ? 'text-secondary' : 'text-quaternary')}>{r.summary.fixable}</span>,
  },
  {
    header: 'KEV',
    className: 'w-12 text-right',
    cell: (r) => <span className={cn('font-mono text-sm tabular-nums', r.summary.kev ? 'font-semibold text-critical' : 'text-quaternary')}>{r.summary.kev}</span>,
  },
  { header: 'Scan', className: 'w-32', cell: (r) => <HostScanBadge row={r} /> },
  {
    header: 'Recorded',
    className: 'w-36 tabular-nums',
    cell: (r) => <span className="text-tertiary" title={r.recordedAt ?? undefined}>{formatFleetTime(r.recordedAt ?? '')}</span>,
  },
]

export function Hosts() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState<StateFilter>('all')
  const [query, setQuery] = useState('')
  const { data: rows, loading, error, refetch } = useFetch<HostRow[]>(() => api.listHosts(), { deps: [] })

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (rows ?? []).filter((r) => matchesFilter(r, filter) && matchesSearch(r, q))
  }, [rows, filter, query])

  if (error && isFeatureDisabledMessage(error)) {
    return (
      <FeatureDisabledState
        feature="Fleet host inventory"
        envVar="SYNAPSE_FLEET_HOST_INGEST_ENABLED"
        hint="Host vulnerabilities need the fleet asset model and host inventory ingest. Enrol a synapse-agent once they are on."
      />
    )
  }

  const all = rows ?? []
  const strip = {
    hosts: all.length,
    vulnerable: all.filter((r) => r.summary.total > 0).length,
    critical: all.reduce((n, r) => n + r.summary.critical, 0),
    high: all.reduce((n, r) => n + r.summary.high, 0),
    kev: all.reduce((n, r) => n + r.summary.kev, 0),
    noInventory: all.filter((r) => { const s = hostScanState(r); return s === 'none' || s === 'unrecorded' }).length,
    failed: all.filter((r) => hostScanState(r) === 'failed').length,
  }
  const lastRecorded = all.reduce<string | null>((latest, r) => (r.recordedAt && (!latest || r.recordedAt > latest) ? r.recordedAt : latest), null)

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-5 pb-12">
      <header className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h1 className="text-2xl font-bold tracking-tight text-primary">Hosts</h1>
        <span className="text-xs text-tertiary">
          {lastRecorded ? `Last package set recorded ${formatFleetTime(lastRecorded)}` : all.length ? 'No package set recorded yet' : ''}
        </span>
      </header>

      {rows && rows.length > 0 && (
        <MetricStrip ariaLabel="Host fleet summary">
          <Metric label="Hosts" value={strip.hosts} />
          <Metric label="With findings" value={strip.vulnerable} tone={strip.vulnerable ? 'high' : 'muted'} />
          <Metric label="Critical" value={strip.critical} tone="critical" />
          <Metric label="High" value={strip.high} tone="high" />
          <Metric label="Known exploited" value={strip.kev} tone="critical" />
          <Metric label="No inventory" value={strip.noInventory} tone={strip.noInventory ? 'warning' : 'muted'} />
          <Metric label="Scan failed" value={strip.failed} tone={strip.failed ? 'warning' : 'muted'} />
        </MetricStrip>
      )}

      <Card bodyClass="p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-secondary px-4 py-3">
          <div className="relative min-w-[16rem] flex-1">
            <SearchSm className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
            <Input
              aria-label="Search hosts"
              placeholder="Search host, machine id, agent, OS, cloud instance"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="pl-9"
            />
          </div>
          <div className="flex flex-wrap gap-1" role="group" aria-label="Filter hosts">
            {FILTERS.map((f) => (
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
              </button>
            ))}
          </div>
          {rows && (
            <span className="ml-auto font-mono text-xs tabular-nums text-quaternary">
              {visible.length === rows.length ? `${rows.length} hosts` : `${visible.length} of ${rows.length} hosts`}
            </span>
          )}
        </div>

        {error ? (
          <OperationalState
            tone="error"
            title="Could not load hosts"
            detail={error}
            meta={[`observed ${new Date().toISOString()}`]}
            onRetry={refetch}
          />
        ) : loading && !rows ? (
          <TableSkeleton rows={6} columns={7} />
        ) : rows && rows.length === 0 ? (
          <OperationalState
            title="No hosts received yet"
            detail="A host appears after an enrolled synapse-agent posts its first inventory. Packages it reports are scanned on the same sync."
            action={<Button variant="secondary" onClick={() => navigate('/fleet')}>Open fleet agents</Button>}
          />
        ) : visible.length === 0 ? (
          <OperationalState
            title="No hosts match"
            detail="No host matches the current filter and search."
            action={<Button variant="secondary" onClick={() => { setFilter('all'); setQuery('') }}>Clear filters</Button>}
          />
        ) : (
          <VirtualTable
            items={visible}
            columns={COLUMNS}
            rowKey={(r) => r.asset.id}
            onRowClick={(r) => navigate(`/fleet/hosts/${encodeURIComponent(r.asset.id)}`)}
            rowAriaLabel={(r) => `Open host ${r.asset.name || r.asset.key}`}
            maxHeightClass="max-h-[72vh]"
            tableMinWidthClass="min-w-[64rem]"
          />
        )}
      </Card>
    </div>
  )
}
