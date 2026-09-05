import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Server02, ShieldTick } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { HostFinding, HostVulnerabilities } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, Pill, SevBadge, Spinner, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabledMessage } from '../../components/synapse/FeatureDisabledState'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import { HostScanBadge, SeverityCount, hostDegraded, hostFindingAdvisory, hostFindingPackage, hostOS, hostScanState } from './hostShared'

const COLUMNS: Column<HostFinding>[] = [
  {
    header: 'Advisory',
    className: 'w-56',
    cell: (f) => (
      <div className="min-w-0">
        <div className="truncate font-mono text-sm text-primary" title={f.title}>{hostFindingAdvisory(f)}</div>
        {f.kev && <span className="text-[11px] font-semibold text-critical">Known exploited</span>}
      </div>
    ),
  },
  {
    header: 'Package',
    className: 'flex-1 min-w-0',
    cell: (f) => {
      const pkg = hostFindingPackage(f)
      return (
        <div className="min-w-0">
          <div className="truncate text-primary" title={pkg.name || f.title}>{pkg.name || f.title}</div>
          {pkg.version && <div className="truncate font-mono text-[11px] text-quaternary" title={pkg.version}>{pkg.version}</div>}
        </div>
      )
    },
  },
  { header: 'Severity', className: 'w-28', cell: (f) => <SevBadge sev={f.severity} /> },
  {
    header: 'CVSS',
    className: 'w-20 text-right',
    cell: (f) => (
      <span className={cn('font-mono text-sm tabular-nums', f.cvssScore ? 'text-secondary' : 'text-quaternary')} title={f.cvssVector || undefined}>
        {f.cvssScore ? f.cvssScore.toFixed(1) : '—'}
      </span>
    ),
  },
  {
    header: 'Fixed in',
    className: 'w-44',
    cell: (f) => (f.fixedVersion
      ? <span className="truncate font-mono text-[12px] text-secondary" title={f.fixedVersion}>{f.fixedVersion}</span>
      : <span className="text-xs text-quaternary">No fix published</span>),
  },
  {
    header: 'Sources',
    className: 'w-36',
    cell: (f) => <span className="truncate text-xs text-tertiary" title={f.sources.join(', ')}>{f.sources.length ? f.sources.join(', ') : '—'}</span>,
  },
  {
    header: 'Status',
    className: 'w-24',
    cell: (f) => <span className="text-xs capitalize text-tertiary">{f.status.replace(/_/g, ' ')}</span>,
  },
]

function BackLink() {
  return (
    <Link to="/fleet/hosts" className="inline-flex items-center gap-1 text-sm text-tertiary hover:text-primary">
      <ArrowLeft className="size-4" /> Hosts
    </Link>
  )
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs uppercase tracking-wide text-quaternary">{label}</dt>
      <dd className={cn('truncate text-sm text-primary', mono && 'font-mono text-[12px]')} title={value}>{value || '—'}</dd>
    </div>
  )
}

function FindingsBody({ host }: { host: HostVulnerabilities }) {
  const state = hostScanState(host)
  if (state === 'none') {
    return (
      <EmptyState
        icon={Server02}
        title="No packages reported yet"
        hint="The agent has not sent an OS package list for this host, so there is nothing to correlate. Packages are scanned on the sync that reports them."
      />
    )
  }
  if (host.findings.length === 0) {
    if (state === 'running') {
      return <EmptyState icon={Server02} title="Scan in progress" hint={`The ${host.packages} reported packages are being matched against advisories.`} />
    }
    if (state === 'failed') {
      return <EmptyState icon={Server02} title="The last scan failed" hint={host.lastScan?.error || 'The pipeline reported an error; the next inventory sync retries the scan.'} />
    }
    return <EmptyState icon={ShieldTick} title="No known vulnerabilities" hint={`None of the ${host.packages} reported packages matches an open advisory as of the last scan.`} />
  }
  return (
    <VirtualTable
      items={host.findings}
      columns={COLUMNS}
      rowKey={(f) => f.id}
      maxHeightClass="max-h-[65vh]"
      tableMinWidthClass="min-w-[68rem]"
    />
  )
}

export function HostDetail() {
  const { id = '' } = useParams()
  const { data: host, loading, error, refetch } = useFetch<HostVulnerabilities>(() => api.hostVulnerabilities(id), { deps: [id] })

  if (loading && !host) return <div className="p-8"><Spinner label="Loading host…" /></div>
  if (error && !host) {
    if (isFeatureDisabledMessage(error)) {
      return <FeatureDisabledState feature="Fleet host inventory" envVar="SYNAPSE_FLEET_HOST_INGEST_ENABLED" hint="Host vulnerabilities need the fleet asset model and host inventory ingest." />
    }
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4">
        <BackLink />
        <ErrorState message={error} />
        <Button variant="secondary" onClick={refetch}>Retry</Button>
      </div>
    )
  }
  if (!host) return null

  const a = host.asset.attributes
  const s = host.summary

  return (
    <div className="mx-auto max-w-[1400px] animate-fade-in space-y-6 pb-12">
      <BackLink />

      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-primary">{host.asset.name || host.asset.key}</h1>
          <HostScanBadge row={host} />
          {hostDegraded(host) && <Pill className="bg-warning-primary text-warning-primary">Incomplete inventory</Pill>}
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-tertiary">
          <span className="font-mono">{host.asset.key}</span>
          <span>· {hostOS(host)}</span>
          {a.arch && <span>· {a.arch}</span>}
          {host.recordedAt && <span>· Packages recorded {formatFleetTime(host.recordedAt)}</span>}
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <div className="space-y-6">
          <Card title={`Vulnerabilities${host.findings.length ? ` (${host.findings.length})` : ''}`} bodyClass="p-0">
            <FindingsBody host={host} />
          </Card>
        </div>

        <aside className="space-y-6">
          <Card title="Exposure">
            <dl className="grid grid-cols-2 gap-4">
              <div><dt className="text-xs uppercase tracking-wide text-quaternary">Critical</dt><dd><SeverityCount count={s.critical} tone="critical" /></dd></div>
              <div><dt className="text-xs uppercase tracking-wide text-quaternary">High</dt><dd><SeverityCount count={s.high} tone="high" /></dd></div>
              <div><dt className="text-xs uppercase tracking-wide text-quaternary">Medium</dt><dd><SeverityCount count={s.medium} tone="medium" /></dd></div>
              <div><dt className="text-xs uppercase tracking-wide text-quaternary">Low</dt><dd><SeverityCount count={s.low} tone="low" /></dd></div>
              <div><dt className="text-xs uppercase tracking-wide text-quaternary">Fixable</dt><dd className="font-mono text-sm tabular-nums text-primary">{s.fixable}<span className="text-quaternary"> / {s.total}</span></dd></div>
              <div><dt className="text-xs uppercase tracking-wide text-quaternary">Known exploited</dt><dd className={cn('font-mono text-sm tabular-nums', s.kev ? 'font-semibold text-critical' : 'text-quaternary')}>{s.kev}</dd></div>
            </dl>
          </Card>

          <Card title="Host">
            <dl className="grid grid-cols-2 gap-4">
              <Fact label="OS" value={hostOS(host)} />
              <Fact label="Kernel" value={a.kernel ?? ''} mono />
              <Fact label="Architecture" value={a.arch ?? ''} />
              <Fact label="Packages" value={host.packages ? String(host.packages) : (a.packages ?? '0')} />
              <Fact label="Machine id" value={a.machine_id ?? ''} mono />
              <Fact label="Cloud instance" value={a.cloud_instance ?? ''} mono />
              <Fact label="Reporting agent" value={a.reporting_agent_id ?? ''} mono />
              <Fact label="Coverage gaps" value={a.coverage_gaps ?? '0'} />
            </dl>
          </Card>

          {host.lastScan && (
            <Card title="Last scan">
              <dl className="grid grid-cols-2 gap-4">
                <Fact label="Status" value={host.lastScan.status} />
                <Fact label="Stage" value={host.lastScan.stage} />
                <Fact label="Started" value={formatFleetTime(host.lastScan.startedAt ?? '')} />
                <Fact label="Finished" value={formatFleetTime(host.lastScan.finishedAt ?? '')} />
                {host.lastScan.error && <div className="col-span-2"><dt className="text-xs uppercase tracking-wide text-quaternary">Error</dt><dd className="text-sm text-error-primary">{host.lastScan.error}</dd></div>}
                <Fact label="Job" value={host.lastScan.jobId} mono />
              </dl>
            </Card>
          )}
        </aside>
      </div>
    </div>
  )
}
