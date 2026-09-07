import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Copy01, RefreshCcw01, SearchSm, Trash01, XClose } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { DesiredCapabilities, EndpointProcess, RetroHuntResult } from '../../lib/api'
import type { FleetDesiredGap, HostFinding, HostPackages, HostVulnerabilities, Severity } from '../../lib/types'
import { Button, Card, InfoNote, Input, Pill, SevBadge, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabledMessage } from '../../components/synapse/FeatureDisabledState'
import { Metric, MetricStrip } from '../../components/synapse/Metric'
import { OperationalState, TableSkeleton } from '../../components/synapse/OperationalState'
import { VirtualTable, type Column } from '../../components/synapse/VirtualTable'
import { useFetch } from '../../hooks'
import { formatFleetTime } from './fleetShared'
import { HostScanBadge, hostDegraded, hostFindingAdvisory, hostFindingPackage, hostOS, hostScanState, hostShortName, reportedPackages } from './hostShared'

type Tab = 'vulnerabilities' | 'packages' | 'coverage' | 'capabilities' | 'processes' | 'retrohunt'
type SeverityFilter = 'all' | Severity | 'unrated'
const RATED: Severity[] = ['critical', 'high', 'medium', 'low']
type FixFilter = 'all' | 'fixable' | 'unfixed'

const FINDING_COLUMNS: Column<HostFinding>[] = [
  {
    header: 'Advisory',
    className: 'w-48',
    cell: (f) => <span className="truncate font-mono text-sm text-primary" title={f.title}>{hostFindingAdvisory(f)}</span>,
  },
  { header: 'Severity', className: 'w-24', cell: (f) => <SevBadge sev={f.severity} /> },
  {
    header: 'CVSS',
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
    cell: (f) => <Pill className="bg-secondary text-secondary">{f.status.replace(/_/g, ' ')}</Pill>,
  },
]

/** The stable host key split into what it is and its value: "machine-id/<id>" or "hostname/<name>". */
function hostKeyParts(key: string): [string, string] {
  const slash = key.indexOf('/')
  if (slash <= 0) return ['key', key]
  return [key.slice(0, slash).replace('-', ' '), key.slice(slash + 1)]
}

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
      if (severity === 'unrated' ? RATED.includes(f.severity) : severity !== 'all' && f.severity !== severity) return false
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
  const bySeverity = host.findings.reduce<Partial<Record<Severity, number>>>((acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc }, {})
  // Findings whose advisory carries no severity band; shown so the chips add up to the total.
  const unrated = host.findings.length - RATED.reduce((n, s) => n + (bySeverity[s] ?? 0), 0)
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-secondary px-4 py-3">
        <div className="relative min-w-[14rem] flex-1">
          <SearchSm className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
          <Input aria-label="Search findings" placeholder="Search advisory, package, fix" value={query} onChange={(e) => setQuery(e.target.value)} className="pl-9" />
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by severity">
          {(['all', 'critical', 'high', 'medium', 'low', 'unrated'] as SeverityFilter[]).map((s) => (
            <button key={s} type="button" aria-pressed={severity === s} className={chip(severity === s)} onClick={() => setSeverity(s)}>
              {s === 'all' ? 'All severities' : s[0].toUpperCase() + s.slice(1)}
              {s !== 'all' && <span className="ml-1 font-mono tabular-nums opacity-70">{s === 'unrated' ? unrated : bySeverity[s] ?? 0}</span>}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by fix">
          {([['all', 'Any fix state'], ['fixable', 'Fix available'], ['unfixed', 'No fix']] as [FixFilter, string][]).map(([v, l]) => (
            <button key={v} type="button" aria-pressed={fix === v} className={chip(fix === v)} onClick={() => setFix(v)}>{l}</button>
          ))}
        </div>
        <button type="button" aria-pressed={kevOnly} className={chip(kevOnly)} onClick={() => setKevOnly((v) => !v)}>
          Known exploited<span className="ml-1 font-mono tabular-nums opacity-70">{host.summary.kev}</span>
        </button>
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

/** What each declared coverage gap means for the findings on this host. */
const COVERAGE_KIND: Record<string, { label: string; effect: string }> = {
  'unreadable-package-db': { label: 'Package database unreadable', effect: 'The package list is incomplete, so vulnerability findings for the unread packages are missing.' },
  'no-package-db': { label: 'No package database', effect: 'No supported package database was found; no OS packages were inventoried.' },
  'unsupported-platform': { label: 'Unsupported platform', effect: 'The agent cannot inventory this operating system; nothing here is measured.' },
  'missing-fact': { label: 'Host fact missing', effect: 'A host fact could not be determined; identity or OS matching may be weaker.' },
  'not-collected': { label: 'Not collected', effect: 'This dimension is not gathered in this release; its absence is declared, not implied.' },
}

function coverageGaps(host: HostVulnerabilities): { kind: string; detail: string }[] {
  const kinds = (host.asset.attributes.coverage_gap_kinds ?? '').split(',').map((k) => k.trim()).filter(Boolean)
  const details = new Map<string, string[]>()
  for (const line of (host.asset.attributes.coverage_gap_details ?? '').split('\n')) {
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    const kind = line.slice(0, colon).trim()
    details.set(kind, [...(details.get(kind) ?? []), line.slice(colon + 1).trim()])
  }
  return kinds.map((kind) => ({ kind, detail: details.get(kind)?.shift() ?? '' }))
}

function CoverageBody({ host }: { host: HostVulnerabilities }) {
  const declared = Number(host.asset.attributes.coverage_gaps ?? '0') || 0
  const gaps = coverageGaps(host)
  if (declared === 0) {
    return <OperationalState tone="success" title="Full coverage" detail="The agent read every package database it found and reported every fact it collects." />
  }
  if (gaps.length === 0) {
    return (
      <OperationalState
        title="Gap details not recorded"
        detail={`The agent declared ${declared} coverage ${declared === 1 ? 'gap' : 'gaps'} but this host was last synced by a server that stored the count only. The next inventory sync records each gap's kind and detail.`}
      />
    )
  }
  return (
    <div className="divide-y divide-secondary">
      {gaps.map((gap, i) => {
        const meta = COVERAGE_KIND[gap.kind] ?? { label: gap.kind, effect: 'Undocumented gap kind reported by the agent.' }
        return (
          <div key={`${gap.kind}-${i}`} className="grid gap-x-6 gap-y-1 px-4 py-3 sm:grid-cols-[14rem_1fr]">
            <div>
              <div className="text-sm font-medium text-primary">{meta.label}</div>
              <div className="font-mono text-[11px] text-quaternary">{gap.kind}</div>
            </div>
            <div className="min-w-0">
              {gap.detail && <div className="truncate font-mono text-xs text-secondary" title={gap.detail}>{gap.detail}</div>}
              <div className="text-xs text-tertiary">{meta.effect}</div>
            </div>
          </div>
        )
      })}
    </div>
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

function toLocalInput(d: Date): string {
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
}

export function RetroHuntBody({ assetId }: { assetId: string }) {
  const localZone = (() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local'
    } catch {
      return 'local'
    }
  })()
  const [around, setAround] = useState(() => toLocalInput(new Date()))
  const [beforeMin, setBeforeMin] = useState(15)
  const [afterMin, setAfterMin] = useState(15)
  const [entityId, setEntityId] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [result, setResult] = useState<RetroHuntResult | null>(null)

  async function run() {
    setBusy(true)
    setErr('')
    try {
      const iso = around ? new Date(around).toISOString() : ''
      const res = await api.retroHunt(assetId, {
        around: iso,
        beforeSeconds: Math.max(0, Math.round(beforeMin * 60)),
        afterSeconds: Math.max(0, Math.round(afterMin * 60)),
        entityId: entityId.trim() || undefined,
        limit: 500,
      })
      setResult(res)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Retro-hunt failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4 p-4">
      <p className="text-xs text-tertiary">
        Re-hunt this host's endpoint state timeline in a window around a pivot time, optionally scoped to
        one entity. The window is anchored to the pivot; a capped window is reported as truncated.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">
            Pivot time <span className="font-normal normal-case text-quaternary">({localZone})</span>
          </span>
          <Input type="datetime-local" value={around} onChange={(e) => setAround(e.target.value)} aria-label="Retro-hunt pivot time" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Look back (min)</span>
          <Input type="number" min={0} value={beforeMin} onChange={(e) => setBeforeMin(Number(e.target.value) || 0)} className="w-28" aria-label="Retro-hunt look-back minutes" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Look forward (min)</span>
          <Input type="number" min={0} value={afterMin} onChange={(e) => setAfterMin(Number(e.target.value) || 0)} className="w-28" aria-label="Retro-hunt look-forward minutes" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Entity (optional)</span>
          <Input value={entityId} onChange={(e) => setEntityId(e.target.value)} placeholder="entity id" className="w-48 font-mono" aria-label="Retro-hunt entity id" />
        </label>
        <Button variant="primary" className="px-3 py-2" loading={busy} disabled={busy || (beforeMin === 0 && afterMin === 0)} onClick={run}>
          <SearchSm className="size-4" /> Hunt
        </Button>
      </div>
      {beforeMin === 0 && afterMin === 0 && (
        <p className="text-xs text-warning-primary">Set a non-zero look-back or look-forward; a zero-width window is rejected.</p>
      )}
      {err && <OperationalState tone="error" title="Retro-hunt failed" detail={err} />}
      {result && !err && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-xs text-tertiary">
            <span>{formatFleetTime(result.from)} → {formatFleetTime(result.to)}</span>
            <Pill>{result.entries.length} transition{result.entries.length === 1 ? '' : 's'}</Pill>
            {result.truncated ? (
              <Pill className="bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25">
                truncated — window capped
              </Pill>
            ) : (
              <Pill className="bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25">complete window</Pill>
            )}
          </div>
          {result.entries.length === 0 ? (
            <p className="text-sm text-tertiary">No endpoint transitions in this window.</p>
          ) : (
            <ol className="relative space-y-2 border-l border-secondary pl-4">
              {result.entries.map((en) => (
                <li key={en.eventId || `${en.occurredAt}-${en.entityId}`} className="relative">
                  <span className="absolute -left-[21px] top-1.5 size-2 rounded-full bg-brand-solid" aria-hidden />
                  <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
                    <span className="inline-block w-40 shrink-0 font-mono text-xs tabular-nums text-secondary">{formatFleetTime(en.occurredAt)}</span>
                    <span className="text-sm font-medium text-primary">{en.kind}</span>
                    {en.entityKind && <Pill className="capitalize">{en.entityKind}</Pill>}
                    {en.entityId && <span className="font-mono text-xs text-quaternary">{en.entityId}</span>}
                  </div>
                  {en.summary && <p className="mt-0.5 text-sm text-tertiary">{en.summary}</p>}
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  )
}

const GAP_REASON_LABEL: Record<string, string> = {
  agent_missing: 'No agent assigned',
  agent_stale: 'Agent stale',
  agent_revoked: 'Agent revoked',
  agent_decommissioned: 'Agent decommissioned',
  capability_missing: 'Capability not run',
}

/** Desired capabilities: the capabilities an operator declares this host must run, reconciled against
 *  what its agent actually reports. The declared set is editable; the reconciliation shows the gaps. */
function CapabilitiesBody({ assetId, canOperate }: { assetId: string; canOperate: boolean }) {
  const { data: desired, loading, error, refetch } = useFetch<DesiredCapabilities | null>(() => api.getDesiredCapabilities(assetId), { deps: [assetId] })
  const { data: gaps, refetch: refetchGaps } = useFetch<FleetDesiredGap[]>(() => api.fleetDesiredGaps(), { deps: [assetId] })
  const assetGaps = useMemo(() => (gaps ?? []).filter((g) => g.assetId === assetId), [gaps, assetId])
  const [draft, setDraft] = useState<string[]>([])
  const [entry, setEntry] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    setDraft(desired?.capabilities ?? [])
  }, [desired])

  const dirty = useMemo(() => {
    const a = [...draft].sort()
    const b = [...(desired?.capabilities ?? [])].sort()
    return a.length !== b.length || a.some((v, i) => v !== b[i])
  }, [draft, desired])

  function addEntry() {
    const v = entry.trim()
    if (!v || draft.includes(v)) {
      setEntry('')
      return
    }
    setDraft((d) => [...d, v])
    setEntry('')
  }

  async function save() {
    setBusy(true)
    setErr('')
    try {
      await api.setDesiredCapabilities(assetId, draft)
      await Promise.all([refetch(), refetchGaps()])
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not save desired capabilities')
    } finally {
      setBusy(false)
    }
  }

  async function clearAll() {
    if (!window.confirm('Remove the declared desired capabilities for this host? Reconciliation will no longer flag missing capabilities.')) return
    setBusy(true)
    setErr('')
    try {
      await api.clearDesiredCapabilities(assetId)
      await Promise.all([refetch(), refetchGaps()])
      setDraft([])
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not clear desired capabilities')
    } finally {
      setBusy(false)
    }
  }

  if (error) return <OperationalState tone="error" title="Could not load desired capabilities" detail={error} onRetry={refetch} />
  if (loading && desired === undefined) return <TableSkeleton rows={4} columns={2} />

  return (
    <div className="space-y-5 p-4">
      <section className="space-y-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-primary">Declared capabilities</h3>
          <InfoNote label="What is this">
            The capabilities an operator requires this host to run. The server reconciles the declared set
            against what the host's agent actually reports; anything declared but not observed is a gap below.
          </InfoNote>
          {desired && <span className="font-mono text-xs text-quaternary">v{desired.version}{desired.updatedAt ? ` · updated ${formatFleetTime(desired.updatedAt)}` : ''}</span>}
        </div>
        {canOperate ? (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-2">
              {draft.length === 0 && <span className="text-sm text-tertiary">None declared.</span>}
              {draft.map((c) => (
                <span key={c} className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-1 font-mono text-xs text-secondary">
                  {c}
                  <button type="button" aria-label={`Remove ${c}`} className="text-quaternary hover:text-primary" onClick={() => setDraft((d) => d.filter((x) => x !== c))}>
                    <XClose className="size-3.5" />
                  </button>
                </span>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                aria-label="Add capability"
                placeholder="capability id, e.g. edr.process"
                value={entry}
                onChange={(e) => setEntry(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addEntry() } }}
                className="w-64 font-mono"
              />
              <Button variant="secondary" onClick={addEntry} disabled={!entry.trim()}>Add</Button>
              <Button variant="primary" loading={busy} disabled={busy || !dirty} onClick={save}>Save</Button>
              {desired && <Button variant="ghost" loading={busy} disabled={busy} onClick={clearAll}><Trash01 className="size-4" /> Clear</Button>}
            </div>
          </div>
        ) : draft.length === 0 ? (
          <p className="text-sm text-tertiary">No desired capabilities are declared for this host.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {draft.map((c) => <span key={c} className="rounded-md bg-secondary px-2 py-1 font-mono text-xs text-secondary">{c}</span>)}
          </div>
        )}
        {err && <p className="text-sm text-error-primary">{err}</p>}
      </section>

      <section className="space-y-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-primary">Reconciliation</h3>
          <InfoNote label="What is this">
            Desired-vs-observed per capability. A row is covered when a healthy agent reports the capability;
            otherwise the reason it is not (no agent, stale, revoked, or the capability was never run).
          </InfoNote>
        </div>
        {assetGaps.length === 0 ? (
          <OperationalState tone={draft.length ? 'success' : 'neutral'} title={draft.length ? 'All declared capabilities are covered' : 'Nothing to reconcile'} detail={draft.length ? 'A healthy agent reports every declared capability for this host.' : 'Declare a capability above to reconcile it against what the agent reports.'} />
        ) : (
          <div className="overflow-hidden rounded-lg border border-secondary">
            <table className="w-full text-sm">
              <thead className="bg-secondary/40 text-left text-xs uppercase tracking-wide text-quaternary">
                <tr><th className="px-3 py-2 font-medium">Capability</th><th className="px-3 py-2 font-medium">State</th><th className="px-3 py-2 font-medium">Agent</th><th className="px-3 py-2 font-medium">Last seen</th></tr>
              </thead>
              <tbody className="divide-y divide-secondary">
                {assetGaps.map((g, i) => (
                  <tr key={`${g.capability}-${i}`}>
                    <td className="px-3 py-2 font-mono text-secondary">{g.capability}</td>
                    <td className="px-3 py-2">
                      {g.covered ? (
                        <Pill className="bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25">covered</Pill>
                      ) : (
                        <Pill className="bg-warning-primary/10 text-warning-primary ring-1 ring-inset ring-warning-primary/25">{GAP_REASON_LABEL[g.gapReason] ?? 'gap'}</Pill>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-tertiary">{g.agentId || '—'}{g.agentHealth ? ` (${g.agentHealth})` : ''}</td>
                    <td className="px-3 py-2 text-xs text-tertiary">{formatFleetTime(g.lastSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

const PROCESS_COLUMNS: Column<EndpointProcess>[] = [
  { header: 'PID', className: 'w-20', cell: (p) => <span className="font-mono text-sm tabular-nums text-secondary">{p.pid}</span> },
  { header: 'Command', className: 'w-40', cell: (p) => <span className="truncate font-mono text-sm text-primary" title={p.comm}>{p.comm || '—'}</span> },
  { header: 'Path', cell: (p) => <span className="truncate font-mono text-xs text-tertiary" title={p.path}>{p.path || '—'}</span> },
  { header: 'State', className: 'w-24', cell: (p) => p.running ? <Pill className="bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25">running</Pill> : <Pill>exited</Pill> },
  { header: 'Last seen', className: 'w-44', cell: (p) => <span className="text-xs tabular-nums text-tertiary">{formatFleetTime(p.lastSeenAt)}</span> },
]

/** The host's running-process projection (the input to the behavior baseline), plus a rebaseline action. */
function ProcessesBody({ assetId, canOperate }: { assetId: string; canOperate: boolean }) {
  const { data, loading, error, refetch } = useFetch<EndpointProcess[]>(() => api.listEndpointProcesses(assetId), { deps: [assetId] })
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [err, setErr] = useState('')
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (data ?? []).filter((p) => !q || `${p.comm} ${p.path} ${p.pid}`.toLowerCase().includes(q))
  }, [data, query])

  async function rebaseline() {
    if (!window.confirm('Reset this host’s behavior baseline? Anomaly scoring re-learns from scratch and will not flag drift until the new baseline settles.')) return
    setBusy(true)
    setErr('')
    setNotice('')
    try {
      await api.rebaselineBehavior(assetId)
      setNotice('Behavior baseline reset. The next telemetry sweep starts the new baseline.')
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Rebaseline failed')
    } finally {
      setBusy(false)
    }
  }

  if (error) return <OperationalState tone="error" title="Could not load processes" detail={error} onRetry={refetch} />
  if (loading && !data) return <TableSkeleton rows={8} columns={5} />

  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-secondary px-4 py-3">
        <div className="relative min-w-[14rem] flex-1">
          <SearchSm className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
          <Input aria-label="Search processes" placeholder="Search command, path, pid" value={query} onChange={(e) => setQuery(e.target.value)} className="pl-9" />
        </div>
        <div className="flex items-center gap-2">
          <InfoNote label="Behavior baseline">
            The running-process set is one input to the statistical behavior baseline. Rebaselining discards the
            learned baseline so scoring re-learns; drift is not flagged until the new baseline settles.
          </InfoNote>
          {canOperate && <Button variant="secondary" loading={busy} disabled={busy} onClick={rebaseline}><RefreshCcw01 className="size-4" /> Rebaseline</Button>}
          <span className="font-mono text-xs tabular-nums text-quaternary">
            {visible.length === (data?.length ?? 0) ? `${data?.length ?? 0} processes` : `${visible.length} of ${data?.length ?? 0} processes`}
          </span>
        </div>
      </div>
      {notice && <p className="border-b border-secondary bg-success-primary/5 px-4 py-2 text-sm text-success-primary">{notice}</p>}
      {err && <p className="border-b border-secondary bg-error-primary/5 px-4 py-2 text-sm text-error-primary">{err}</p>}
      {(data?.length ?? 0) === 0 ? (
        <OperationalState title="No processes reported" detail="The host's agent has not reported a running-process snapshot. Processes appear once the endpoint agent reports them." />
      ) : visible.length === 0 ? (
        <OperationalState title="No processes match" detail="No process matches the current filter." action={<Button variant="secondary" onClick={() => setQuery('')}>Clear filter</Button>} />
      ) : (
        <VirtualTable items={visible} columns={PROCESS_COLUMNS} rowKey={(p) => `${p.entityId || p.pid}-${p.comm}`} maxHeightClass="max-h-[62vh]" tableMinWidthClass="min-w-[56rem]" />
      )}
    </>
  )
}

export function HostDetail() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<Tab>('vulnerabilities')
  const { data: host, loading, error, refetch } = useFetch<HostVulnerabilities>(() => api.hostVulnerabilities(id), { deps: [id] })
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canOperate = me?.role === 'admin' || me?.role === 'consultant' || me?.role === 'member'

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
  const reported = reportedPackages(host)
  const title = hostShortName(host.asset.name, host.asset.key)
  const [keyLabel, keyValue] = hostKeyParts(host.asset.key)

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
          <span className="inline-flex items-center gap-1.5" title={host.asset.key}>
            <span className="text-[10px] font-semibold uppercase tracking-wide text-quaternary">{keyLabel}</span>
            <span className="font-mono text-[12px] text-secondary">{keyValue}</span>
            <CopyButton value={keyValue} label={keyLabel} />
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
        <Metric label="Coverage gaps" value={Number(a.coverage_gaps ?? '0') || 0} tone={hostDegraded(host) ? 'warning' : 'muted'} />
      </MetricStrip>

      <Card bodyClass="p-0">
        <div className="flex items-center gap-1 border-b border-secondary px-2" role="tablist" aria-label="Host views">
          {([['vulnerabilities', `Vulnerabilities`, host.findings.length], ['packages', 'Packages', host.packages || reported], ['coverage', 'Coverage gaps', Number(a.coverage_gaps ?? '0') || 0], ['capabilities', 'Capabilities', null], ['processes', 'Processes', null], ['retrohunt', 'Timeline', null]] as [Tab, string, number | null][]).map(([value, label, count]) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={tab === value}
              onClick={() => setTab(value)}
              className={cn('-mb-px border-b-2 px-3 py-2.5 text-sm font-semibold transition-colors', tab === value ? 'border-brand-solid text-primary' : 'border-transparent text-tertiary hover:text-primary')}
            >
              {label}{' '}
              {count !== null && <span className="font-mono text-xs tabular-nums text-quaternary">{count.toLocaleString()}</span>}
            </button>
          ))}
        </div>
        {tab === 'vulnerabilities' ? (
          <VulnerabilitiesBody host={host} />
        ) : tab === 'packages' ? (
          <PackagesBody assetId={host.asset.id} />
        ) : tab === 'capabilities' ? (
          <CapabilitiesBody assetId={host.asset.id} canOperate={canOperate} />
        ) : tab === 'processes' ? (
          <ProcessesBody assetId={host.asset.id} canOperate={canOperate} />
        ) : tab === 'retrohunt' ? (
          <RetroHuntBody assetId={host.asset.id} />
        ) : (
          <CoverageBody host={host} />
        )}
      </Card>
    </div>
  )
}
