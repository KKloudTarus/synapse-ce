import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Copy01, SearchSm } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { HostFinding, HostPackages, HostVulnerabilities, Severity } from '../../lib/types'
import { Button, Card, Input, Pill, SevBadge, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabledMessage } from '../../components/synapse/FeatureDisabledState'
import { Metric, MetricStrip } from '../../components/synapse/Metric'
import { OperationalState, TableSkeleton } from '../../components/synapse/OperationalState'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import { HostScanBadge, hostDegraded, hostFindingAdvisory, hostFindingPackage, hostOS, hostScanState, hostShortName, reportedPackages } from './hostShared'

type Tab = 'vulnerabilities' | 'packages'
type SeverityFilter = 'all' | Severity
type FixFilter = 'all' | 'fixable' | 'unfixed'

const FINDING_COLUMNS: Column<HostFinding>[] = [
  {
    header: 'Advisory',
    className: 'w-48',
    cell: (f) => <span className="truncate font-mono text-sm text-primary" title={f.title}>{hostFindingAdvisory(f)}</span>,
  },
  { header: 'Severity', className: 'w-24', cell: (f) => <SevBadge sev={f.severity} /> },
  {
    header: 'CVSS / KEV',
    className: 'w-28',
    cell: (f) => (
      <span className="flex items-baseline gap-2">
        <span className={cn('font-mono text-sm tabular-nums', f.cvssScore ? 'text-secondary' : 'text-quaternary')} title={f.cvssVector || 'no CVSS v3 vector'}>
          {f.cvssScore ? f.cvssScore.toFixed(1) : '—'}
        </span>
        {f.kev && <span className="rounded bg-error-primary px-1 text-[10px] font-semibold uppercase text-error-primary" title="CISA Known Exploited Vulnerabilities">KEV</span>}
      </span>
    ),
  },
  {
    header: 'Package installed',
    className: 'flex-1 min-w-0',
    cell: (f) => {
      const pkg = hostFindingPackage(f)
      return (
        <span className="truncate" title={`${pkg.name} ${pkg.version}`}>
          <span className="text-primary">{pkg.name || f.title}</span>
          {pkg.version && <span className="font-mono text-[12px] text-quaternary"> {pkg.version}</span>}
        </span>
      )
    },
  },
  {
    header: 'Fixed in',
    className: 'w-44',
    cell: (f) => (f.fixedVersion
      ? <span className="truncate font-mono text-[12px] text-secondary" title={f.fixedVersion}>{f.fixedVersion}</span>
      : <span className="text-xs text-quaternary">no fix published</span>),
  },
  {
    header: 'Source',
    className: 'w-28',
    cell: (f) => <span className="truncate text-xs text-tertiary" title={f.sources.join(', ')}>{f.sources.length ? f.sources.join(', ') : '—'}</span>,
  },
  {
    header: 'Status',
    className: 'w-24',
    cell: (f) => <span className="text-xs text-tertiary">{f.status.replace(/_/g, ' ')}</span>,
  },
]

const PACKAGE_COLUMNS: Column<HostPackages['packages'][number]>[] = [
  { header: 'Package', className: 'w-72', cell: (p) => <span className="truncate text-primary" title={p.name}>{p.name}</span> },
  { header: 'Version', className: 'w-64', cell: (p) => <span className="truncate font-mono text-[12px] text-secondary" title={p.version}>{p.version}</span> },
  { header: 'Package URL', className: 'flex-1 min-w-0', cell: (p) => <span className="truncate font-mono text-[11px] text-quaternary" title={p.purl}>{p.purl || '—'}</span> },
]

function BackLink() {
  return (
    <Link to="/fleet/hosts" className="inline-flex items-center gap-1 text-sm text-tertiary hover:text-primary">
      <ArrowLeft className="size-4" /> Hosts
    </Link>
  )
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      aria-label={`Copy ${label}`}
      title={copied ? 'Copied' : `Copy ${label}`}
      className="inline-flex items-center rounded p-0.5 text-quaternary hover:text-primary"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
      }}
    >
      <Copy01 className="size-3.5" />
    </button>
  )
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <span className="inline-flex items-baseline gap-1.5">
      <span className="text-[11px] uppercase tracking-wide text-quaternary">{label}</span>
      <span className={cn('text-sm text-secondary', mono && 'font-mono text-[12px]')} title={value}>{value || '—'}</span>
    </span>
  )
}

function VulnerabilitiesBody({ host }: { host: HostVulnerabilities }) {
  const [severity, setSeverity] = useState<SeverityFilter>('all')
  const [fix, setFix] = useState<FixFilter>('all')
  const [kevOnly, setKevOnly] = useState(false)
  const [query, setQuery] = useState('')
  const state = hostScanState(host)
  const reported = reportedPackages(host)
  const agent = host.asset.attributes.reporting_agent_id ?? ''

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return host.findings.filter((f) => {
      if (severity !== 'all' && f.severity !== severity) return false
      if (fix === 'fixable' && !f.fixedVersion) return false
      if (fix === 'unfixed' && f.fixedVersion) return false
      if (kevOnly && !f.kev) return false
      if (q) {
        const pkg = hostFindingPackage(f)
        const hay = [hostFindingAdvisory(f), f.title, pkg.name, pkg.version, f.fixedVersion, f.sources.join(' ')].join(' ').toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [host.findings, severity, fix, kevOnly, query])

  if (state === 'none') {
    return (
      <OperationalState
        title="Package inventory missing"
        detail={`The agent${agent ? ` ${agent}` : ''} has not sent an OS package list for this host, so vulnerability correlation has nothing to work on. The agent collects dpkg, apk and rpm databases; a coverage gap on the host says which one it could not read.`}
        meta={[`coverage gaps: ${host.asset.attributes.coverage_gaps ?? '0'}`, host.asset.attributes.degraded === 'true' ? 'package database unreadable' : 'no package database reported']}
      />
    )
  }
  if (state === 'unrecorded') {
    return (
      <OperationalState
        tone="error"
        title="Packages reported, none recorded"
        detail={`The agent reported ${reported.toLocaleString()} packages but the server recorded no set for this host, so no scan ran. The inventory sync response and the audit entry host_inventory.vulnerability_scan_failed carry the reason; the next hourly sweep retries.`}
        meta={[`reported ${reported.toLocaleString()} packages`, agent ? `agent ${agent}` : '']}
      />
    )
  }
  if (host.findings.length === 0) {
    if (state === 'pending' || state === 'running') {
      return (
        <OperationalState
          title={state === 'running' ? 'Scan in progress' : 'Scan pending'}
          detail={`${host.packages.toLocaleString()} recorded packages are being matched against advisories.`}
          meta={[host.recordedAt ? `recorded ${formatFleetTime(host.recordedAt)}` : '', host.lastScan ? `stage ${host.lastScan.stage}` : ''].filter(Boolean)}
        />
      )
    }
    if (state === 'failed') {
      return (
        <OperationalState
          tone="error"
          title="The last scan failed"
          detail={host.lastScan?.error || 'The pipeline reported an error. The next inventory sync retries the scan.'}
          meta={[host.lastScan ? `started ${formatFleetTime(host.lastScan.startedAt ?? '')}` : '', host.lastScan ? `job ${host.lastScan.jobId}` : ''].filter(Boolean)}
        />
      )
    }
    return (
      <OperationalState
        tone="success"
        title="No vulnerable OS packages found"
        detail={`None of the ${host.packages.toLocaleString()} recorded packages matches an open advisory.`}
        meta={[host.lastScan ? `scanned ${formatFleetTime(host.lastScan.finishedAt ?? host.lastScan.startedAt ?? '')}` : '', host.recordedAt ? `recorded ${formatFleetTime(host.recordedAt)}` : ''].filter(Boolean)}
      />
    )
  }

  const chip = (active: boolean) => cn('rounded-md px-2.5 py-1 text-xs font-semibold transition-colors', active ? 'bg-brand-solid text-primary_on-brand' : 'text-tertiary hover:bg-secondary')
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-secondary px-4 py-3">
        <div className="relative min-w-[14rem] flex-1">
          <SearchSm className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
          <Input aria-label="Search findings" placeholder="Search advisory, package, fixed version, source" value={query} onChange={(e) => setQuery(e.target.value)} className="pl-9" />
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by severity">
          {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map((s) => (
            <button key={s} type="button" aria-pressed={severity === s} className={chip(severity === s)} onClick={() => setSeverity(s)}>
              {s === 'all' ? 'All severities' : s[0].toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by fix">
          {([['all', 'Any fix state'], ['fixable', 'Fix available'], ['unfixed', 'No fix']] as [FixFilter, string][]).map(([v, l]) => (
            <button key={v} type="button" aria-pressed={fix === v} className={chip(fix === v)} onClick={() => setFix(v)}>{l}</button>
          ))}
        </div>
        <button type="button" aria-pressed={kevOnly} className={chip(kevOnly)} onClick={() => setKevOnly((v) => !v)}>Known exploited only</button>
        <span className="ml-auto font-mono text-xs tabular-nums text-quaternary">
          {visible.length === host.findings.length ? `${host.findings.length} findings` : `${visible.length} of ${host.findings.length} findings`}
        </span>
      </div>
      {visible.length === 0 ? (
        <OperationalState title="No findings match" detail="No finding matches the current filters." action={<Button variant="secondary" onClick={() => { setSeverity('all'); setFix('all'); setKevOnly(false); setQuery('') }}>Clear filters</Button>} />
      ) : (
        <VirtualTable items={visible} columns={FINDING_COLUMNS} rowKey={(f) => f.id} maxHeightClass="max-h-[62vh]" tableMinWidthClass="min-w-[56rem]" />
      )}
    </>
  )
}

function PackagesBody({ assetId }: { assetId: string }) {
  const { data, loading, error, refetch } = useFetch<HostPackages>(() => api.hostPackages(assetId), { deps: [assetId] })
  const [query, setQuery] = useState('')
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (data?.packages ?? []).filter((p) => !q || `${p.name} ${p.version} ${p.purl}`.toLowerCase().includes(q))
  }, [data, query])
  if (error) return <OperationalState tone="error" title="Could not load packages" detail={error} onRetry={refetch} />
  if (loading && !data) return <TableSkeleton rows={8} columns={3} />
  if (!data || data.packages.length === 0) {
    return <OperationalState title="No package set recorded" detail="The server holds no recorded package inventory for this host. The recorded set is the input of the vulnerability scan." />
  }
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-secondary px-4 py-3">
        <div className="relative min-w-[14rem] flex-1">
          <SearchSm className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
          <Input aria-label="Search packages" placeholder="Search package, version, purl" value={query} onChange={(e) => setQuery(e.target.value)} className="pl-9" />
        </div>
        <span className="ml-auto font-mono text-xs tabular-nums text-quaternary">
          {visible.length === data.packages.length ? `${data.packages.length} packages` : `${visible.length} of ${data.packages.length} packages`}
          {data.recordedAt ? ` · recorded ${formatFleetTime(data.recordedAt)}` : ''}
        </span>
      </div>
      <VirtualTable items={visible} columns={PACKAGE_COLUMNS} rowKey={(p) => `${p.name}@${p.version}`} maxHeightClass="max-h-[62vh]" tableMinWidthClass="min-w-[48rem]" />
    </>
  )
}

export function HostDetail() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<Tab>('vulnerabilities')
  const { data: host, loading, error, refetch } = useFetch<HostVulnerabilities>(() => api.hostVulnerabilities(id), { deps: [id] })

  if (loading && !host) return <div className="mx-auto max-w-[1400px] space-y-4 p-4"><BackLink /><TableSkeleton rows={8} columns={6} /></div>
  if (error && !host) {
    if (isFeatureDisabledMessage(error)) {
      return <FeatureDisabledState feature="Fleet host inventory" envVar="SYNAPSE_FLEET_HOST_INGEST_ENABLED" hint="Host vulnerabilities need the fleet asset model and host inventory ingest." />
    }
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4">
        <BackLink />
        <Card bodyClass="p-0"><OperationalState tone="error" title="Could not load this host" detail={error} onRetry={refetch} /></Card>
      </div>
    )
  }
  if (!host) return null

  const a = host.asset.attributes
  const s = host.summary
  const state = hostScanState(host)
  const reported = reportedPackages(host)
  const title = hostShortName(host.asset.name, host.asset.key)

  return (
    <div className="mx-auto max-w-[1400px] animate-fade-in space-y-5 pb-12">
      <BackLink />

      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="max-w-[40rem] truncate text-2xl font-bold tracking-tight text-primary" title={host.asset.name || host.asset.key}>{title}</h1>
          <HostScanBadge row={host} />
          {hostDegraded(host) && <Pill className="bg-warning-primary text-warning-primary">Incomplete inventory</Pill>}
        </div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
          <span className="inline-flex items-center gap-1 font-mono text-[12px] text-tertiary" title={host.asset.key}>
            {host.asset.key}
            <CopyButton value={host.asset.key} label="host key" />
          </span>
          <Fact label="os" value={hostOS(host)} />
          <Fact label="arch" value={a.arch ?? ''} />
          <Fact label="kernel" value={a.kernel ?? ''} mono />
          <Fact label="agent" value={a.reporting_agent_id ?? ''} mono />
          {a.cloud_instance && <Fact label="instance" value={a.cloud_instance} mono />}
          {host.lastScan && <Fact label="last scan" value={formatFleetTime(host.lastScan.finishedAt ?? host.lastScan.startedAt ?? '')} />}
        </div>
      </header>

      <MetricStrip ariaLabel="Host exposure summary">
        <Metric label="Open findings" value={s.total} tone={s.total ? 'high' : 'muted'} />
        <Metric label="Critical" value={s.critical} tone="critical" />
        <Metric label="High" value={s.high} tone="high" />
        <Metric label="Known exploited" value={s.kev} tone="critical" />
        <Metric label="Fixable" value={s.fixable} hint={s.total ? `of ${s.total} with a published fix` : undefined} />
        <Metric label="Packages" value={host.packages || reported} hint={host.recordedAt ? `recorded ${formatFleetTime(host.recordedAt)}` : state === 'unrecorded' ? 'reported, not recorded' : 'none reported'} />
        <Metric label="Coverage gaps" value={Number(a.coverage_gaps ?? '0') || 0} tone={hostDegraded(host) ? 'warning' : 'muted'} />
      </MetricStrip>

      <Card bodyClass="p-0">
        <div className="flex items-center gap-1 border-b border-secondary px-2" role="tablist" aria-label="Host views">
          {([['vulnerabilities', `Vulnerabilities`, host.findings.length], ['packages', 'Packages', host.packages || reported]] as [Tab, string, number][]).map(([value, label, count]) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={tab === value}
              onClick={() => setTab(value)}
              className={cn('-mb-px border-b-2 px-3 py-2.5 text-sm font-semibold transition-colors', tab === value ? 'border-brand-solid text-primary' : 'border-transparent text-tertiary hover:text-primary')}
            >
              {label} <span className="ml-1 font-mono text-xs tabular-nums text-quaternary">{count.toLocaleString()}</span>
            </button>
          ))}
        </div>
        {tab === 'vulnerabilities' ? <VulnerabilitiesBody host={host} /> : <PackagesBody assetId={host.asset.id} />}
      </Card>
    </div>
  )
}
