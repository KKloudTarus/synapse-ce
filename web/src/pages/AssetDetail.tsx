import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Boxes,
  Bug,
  CalendarClock,
  FolderGit2,
  History,
  ListChecks,
  Plus,
  Server,
  ShieldQuestion,
  Target,
  UserRound,
  type LucideIcon,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useOutletContext, useParams } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, SevBadge, Spinner, cn } from '../components/ui'
import { api, ApiError } from '../lib/api'
import type {
  AssetCoverage,
  AssetCoverageVerdict,
  AssetFinding,
  AssetHistoryItem,
  AssetMembership,
  AssetPosture,
  BusinessAsset,
  BusinessAssetCriticality,
  BusinessAssetLifecycle,
  BusinessAssetType,
  Engagement,
} from '../lib/types'
import { PostureBadge } from './Assets'
import { StatusPill } from './Engagements'

type Context = {
  asset: BusinessAsset
  projects: AssetMembership[]
  technical: AssetMembership[]
  engagements: Engagement[]
  findings: AssetFinding[]
  coverage: AssetCoverage
  posture: AssetPosture
  history: AssetHistoryItem[]
  reload: () => void
}

export function useAssetContext() {
  return useOutletContext<Context>()
}

export function AssetDetail() {
  const { key = '' } = useParams()
  const [data, setData] = useState<Context | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    setError(null)
    Promise.all([
      api.getBusinessAsset(key),
      api.businessAssetProjects(key),
      api.businessAssetTechnicalAssets(key),
      api.businessAssetEngagements(key),
      api.businessAssetFindings(key),
      api.businessAssetCoverage(key),
      api.businessAssetPosture(key),
      api.businessAssetHistory(key),
    ])
      .then(([asset, projects, technical, engagements, findings, coverage, posture, history]) => {
        setData({ asset, projects, technical, engagements, findings, coverage, posture, history, reload: load })
      })
      .catch((nextError) => {
        if (nextError instanceof ApiError && nextError.status === 404) setData(null)
        else setError(nextError instanceof Error ? nextError.message : 'Failed to load Asset')
      })
  }, [key])

  useEffect(load, [load])

  if (error) return <div className="mx-auto max-w-6xl"><ErrorState message={error} /></div>
  if (data === undefined) return <Spinner label="Loading Asset…" />
  if (!data) return <EmptyState icon={Boxes} title="Asset not found" hint="It may not exist or belongs to another tenant." />

  const retired = data.asset.lifecycle === 'retired'
  const componentCount = data.projects.length + data.technical.length
  const coveragePercent = data.coverage.rows.length
    ? Math.round(((data.coverage.counts.covered ?? 0) / data.coverage.rows.length) * 100)
    : 0

  return (
    <div className="mx-auto max-w-[1480px] animate-fade-in">
      <Link to="/assets" className="mb-4 inline-flex items-center gap-1.5 text-sm font-medium text-mutedfg hover:text-foreground">
        <ArrowLeft className="size-4" />Asset inventory
      </Link>

      <header className="mb-5 overflow-hidden rounded-xl border border-border bg-card shadow-sm">
        <div className="bg-hero flex flex-wrap items-start justify-between gap-5 p-5 sm:p-7">
          <div className="flex min-w-0 gap-4">
            <span className="hidden size-12 shrink-0 items-center justify-center rounded-xl bg-brand/10 text-branddim sm:flex">
              <Boxes className="size-6" />
            </span>
            <div className="min-w-0">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold uppercase tracking-[0.16em] text-branddim">Asset workspace</span>
                <PostureBadge rating={data.posture.rating} />
              </div>
              <h1 className="truncate text-3xl font-bold tracking-tight sm:text-4xl">{data.asset.name}</h1>
              <p className="mt-1 font-mono text-xs text-subtlefg">{data.asset.key}</p>
              <p className="mt-3 max-w-3xl text-sm leading-6 text-mutedfg">{data.asset.description || 'No description.'}</p>
            </div>
          </div>
          {!retired && (
            <Link
              to={newEngagementPath(data.asset.id)}
              className="btn-primary inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold text-brandfg transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg"
            >
              <Plus className="size-4" />New Engagement
            </Link>
          )}
        </div>
        <div className="flex flex-wrap gap-x-6 gap-y-3 border-t border-border px-5 py-4 text-sm sm:px-7">
          <ProfileItem icon={UserRound} label="Owner" value={data.asset.owner} />
          <ProfileItem icon={Boxes} label="Type" value={data.asset.type.replace('_', ' ')} />
          <ProfileItem icon={AlertTriangle} label="Criticality" value={data.asset.criticality} />
          <ProfileItem icon={Activity} label="Lifecycle" value={data.asset.lifecycle} />
        </div>
      </header>

      {retired && (
        <div className="mb-5 flex items-start gap-3 rounded-xl border border-high/30 bg-high/10 p-4 text-sm text-high">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>This Asset is retired and remains readable for history. Membership and assignment changes are disabled.</span>
        </div>
      )}

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <DetailStat icon={Target} label="Engagements" value={data.engagements.length} />
        <DetailStat icon={Boxes} label="Components" value={componentCount} />
        <DetailStat icon={Bug} label="Current findings" value={data.findings.length} tone={data.findings.length ? 'critical' : 'muted'} />
        <DetailStat icon={ListChecks} label="Coverage" value={`${coveragePercent}%`} tone={coveragePercent === 100 ? 'accent' : 'brand'} />
      </div>

      <nav className="mb-6 flex gap-1 overflow-x-auto rounded-xl border border-border bg-card p-1.5 shadow-sm whitespace-nowrap" aria-label="Asset views">
        <Tab to="." end>Overview</Tab>
        <Tab to="components">Components</Tab>
        <Tab to="engagements">Engagements</Tab>
        <Tab to="findings">Findings</Tab>
        <Tab to="coverage">Coverage</Tab>
        <Tab to="history">History</Tab>
      </nav>
      <Outlet context={data} />
    </div>
  )
}

function newEngagementPath(assetId: string) {
  return `/engagements?${new URLSearchParams({ create: '1', assetId }).toString()}`
}

function ProfileItem({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <span className="flex items-center gap-2 text-mutedfg">
      <Icon className="size-4 text-subtlefg" />
      <span className="text-xs text-subtlefg">{label}</span>
      <span className="font-medium capitalize text-foreground">{value}</span>
    </span>
  )
}

function Tab({ to, end = false, children }: { to: string; end?: boolean; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) => cn(
        'shrink-0 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60',
        isActive ? 'bg-brand/10 text-branddim' : 'text-mutedfg hover:bg-elevated hover:text-foreground',
      )}
    >
      {children}
    </NavLink>
  )
}

function DetailStat({ icon: Icon, label, value, tone = 'muted' }: { icon: LucideIcon; label: string; value: number | string; tone?: 'muted' | 'critical' | 'accent' | 'brand' }) {
  const iconTone = {
    muted: 'bg-muted text-mutedfg',
    critical: 'bg-critical/10 text-critical',
    accent: 'bg-accent/10 text-accent',
    brand: 'bg-brand/10 text-branddim',
  }[tone]
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-2xl font-bold tabular-nums sm:text-3xl">{value}</div>
          <div className="mt-1 text-xs font-medium text-mutedfg sm:text-sm">{label}</div>
        </div>
        <span className={cn('flex size-9 items-center justify-center rounded-lg', iconTone)}><Icon className="size-4" /></span>
      </div>
    </div>
  )
}

export function AssetOverview() {
  const context = useAssetContext()
  return (
    <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
      <Card title="Security posture">
        <div className="flex items-start gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-brand/10 text-branddim">
            <ShieldQuestion className="size-5" />
          </span>
          <div>
            <PostureBadge rating={context.posture.rating} />
            <p className="mt-3 text-sm leading-6 text-mutedfg">{context.posture.explanation}</p>
          </div>
        </div>
        {(Object.keys(context.posture.findingCounts).length > 0 || Object.keys(context.posture.coverageCounts).length > 0) && (
          <div className="mt-5 border-t border-border pt-4">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-subtlefg">Signals</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(context.posture.findingCounts).map(([severity, count]) => <Pill key={severity}>{severity} findings · {count}</Pill>)}
              {Object.entries(context.posture.coverageCounts).map(([verdict, count]) => <Pill key={verdict}>{verdict.replace('_', ' ')} · {count}</Pill>)}
            </div>
          </div>
        )}
      </Card>
      <AssetEditor key={context.asset.version} />
    </div>
  )
}

function AssetEditor() {
  const context = useAssetContext()
  const [name, setName] = useState(context.asset.name)
  const [description, setDescription] = useState(context.asset.description)
  const [owner, setOwner] = useState(context.asset.owner)
  const [type, setType] = useState<BusinessAssetType>(context.asset.type)
  const [criticality, setCriticality] = useState<BusinessAssetCriticality>(context.asset.criticality)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const retired = context.asset.lifecycle === 'retired'
  const next: Partial<Record<BusinessAssetLifecycle, BusinessAssetLifecycle>> = {
    draft: 'active',
    active: 'decommissioning',
    decommissioning: 'retired',
  }

  async function save(lifecycle = context.asset.lifecycle) {
    if (!name.trim() || !owner.trim()) {
      setError('Name and owner are required.')
      return
    }
    setSaving(true)
    setError(null)
    try {
      await api.updateBusinessAsset(context.asset.id, {
        name: name.trim(),
        description: description.trim(),
        owner: owner.trim(),
        type,
        criticality,
        lifecycle,
        version: context.asset.version,
        metadata: context.asset.metadata,
      })
      context.reload()
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Failed to update Asset')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card
      title="Asset profile"
      actions={
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" disabled={retired} loading={saving} onClick={() => save()}>Save</Button>
          {next[context.asset.lifecycle] && (
            <Button variant="brand" disabled={saving} onClick={() => save(next[context.asset.lifecycle])}>
              {next[context.asset.lifecycle] === 'retired' ? 'Retire Asset' : `Move to ${next[context.asset.lifecycle]}`}
            </Button>
          )}
        </div>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><Input value={name} disabled={retired} onChange={(event) => setName(event.target.value)} /></Field>
        <Field label="Owner"><Input value={owner} disabled={retired} onChange={(event) => setOwner(event.target.value)} /></Field>
        <Field label="Type"><Select value={type} disabled={retired} onValueChange={(value) => setType(value as BusinessAssetType)} options={[{ value: 'product', label: 'Product' }, { value: 'application', label: 'Application' }, { value: 'system', label: 'System' }, { value: 'business_service', label: 'Business service' }]} className="w-full" /></Field>
        <Field label="Criticality"><Select value={criticality} disabled={retired} onValueChange={(value) => setCriticality(value as BusinessAssetCriticality)} options={[{ value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }]} className="w-full" /></Field>
        <Field label="Description"><Input value={description} disabled={retired} onChange={(event) => setDescription(event.target.value)} /></Field>
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-mutedfg">Lifecycle / version</div>
          <div className="mt-2 flex gap-2"><Pill>{context.asset.lifecycle}</Pill><Pill>v{context.asset.version}</Pill></div>
        </div>
      </div>
      {error && <div className="mt-4"><ErrorState message={error} /></div>}
    </Card>
  )
}

function MembershipEditor({ title, icon: Icon, items, options, technical = false }: { title: string; icon: typeof Boxes; items: AssetMembership[]; options: { value: string; label: string }[]; technical?: boolean }) {
  const context = useAssetContext()
  const [rows, setRows] = useState(items)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const retired = context.asset.lifecycle === 'retired'
  const known = new Set(options.map((option) => option.value))
  const componentOptions = [
    { value: '', label: 'Select component' },
    ...options,
    ...rows.filter((row) => row.componentId && !known.has(row.componentId)).map((row) => ({ value: row.componentId, label: row.componentId })),
  ]

  async function save() {
    if (rows.some((row) => !row.componentId)) {
      setError('Select a component for every row.')
      return
    }
    setSaving(true)
    setError(null)
    try {
      if (technical) await api.replaceBusinessAssetTechnicalAssets(context.asset.id, rows)
      else await api.replaceBusinessAssetProjects(context.asset.id, rows)
      context.reload()
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Failed to save components')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title={title} actions={<Button variant="secondary" disabled={retired} loading={saving} onClick={save}>Save</Button>}>
      <div className="space-y-3">
        {rows.map((row, index) => (
          <div key={`${row.componentId}-${index}`} className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_150px_minmax(0,1fr)_auto]">
            <Select ariaLabel={`${title} component`} disabled={retired} value={row.componentId} onValueChange={(componentId) => setRows((value) => value.map((item, itemIndex) => itemIndex === index ? { ...item, componentId } : item))} options={componentOptions} className="w-full" />
            <Select ariaLabel={`${title} role`} disabled={retired} value={row.role} onValueChange={(role) => setRows((value) => value.map((item, itemIndex) => itemIndex === index ? { ...item, role: role as AssetMembership['role'] } : item))} options={[{ value: 'primary', label: 'Primary' }, { value: 'supporting', label: 'Supporting' }, { value: 'dependency', label: 'Dependency' }]} className="w-full" />
            <Input aria-label={`${title} provenance`} disabled={retired} value={row.provenance} onChange={(event) => setRows((value) => value.map((item, itemIndex) => itemIndex === index ? { ...item, provenance: event.target.value } : item))} />
            <button type="button" disabled={retired} onClick={() => setRows((value) => value.filter((_, itemIndex) => itemIndex !== index))} className="rounded-lg px-3 text-mutedfg hover:bg-elevated disabled:opacity-40" aria-label="Remove component">×</button>
          </div>
        ))}
        {rows.length === 0 && <div className="flex items-center gap-2 rounded-lg bg-elevated p-4 text-sm text-mutedfg"><Icon className="size-4" />No components linked.</div>}
        <Button variant="secondary" disabled={retired || options.length === 0} onClick={() => setRows((value) => [...value, { componentId: '', role: 'supporting', provenance: 'manual' }])}>Add component</Button>
        {error && <ErrorState message={error} />}
      </div>
    </Card>
  )
}

export function AssetComponents() {
  const context = useAssetContext()
  const [options, setOptions] = useState<{ projects: { value: string; label: string }[]; technical: { value: string; label: string }[] } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      api.listProjects(),
      api.listTechnicalAssets().catch((nextError) => {
        if (nextError instanceof ApiError && nextError.status === 404) return []
        throw nextError
      }),
    ])
      .then(([projects, technical]) => setOptions({
        projects: projects.map((project) => ({ value: project.id, label: `${project.name} · ${project.key}` })),
        technical: technical.map((item) => ({ value: item.id, label: `${item.name} · ${item.kind} · ${item.key}` })),
      }))
      .catch((nextError) => setError(nextError instanceof Error ? nextError.message : 'Failed to load available components'))
  }, [])

  if (error) return <ErrorState message={error} />
  if (!options) return <Spinner label="Loading available components…" />
  return (
    <div className="space-y-5">
      <MembershipEditor title="Projects / repositories" icon={FolderGit2} items={context.projects} options={options.projects} />
      <MembershipEditor title="Technical / fleet assets" icon={Server} items={context.technical} options={options.technical} technical />
    </div>
  )
}

export function AssetEngagements() {
  const context = useAssetContext()
  const action = context.asset.lifecycle !== 'retired' ? (
    <Link to={newEngagementPath(context.asset.id)} className="inline-flex items-center gap-2 text-sm font-semibold text-branddim hover:underline">
      <Plus className="size-4" />New Engagement
    </Link>
  ) : undefined

  if (!context.engagements.length) {
    return <EmptyState icon={Target} title="No Engagements assigned" hint="Create an Engagement from this Asset to preselect the relationship." action={action} />
  }
  return (
    <Card title="Assigned Engagements" actions={action} bodyClass="divide-y divide-border p-0">
      {context.engagements.map((engagement) => (
        <Link key={engagement.id} to={`/engagements/${engagement.id}`} className="flex flex-wrap items-center justify-between gap-3 p-4 transition-colors hover:bg-elevated sm:px-5">
          <div>
            <div className="font-medium">{engagement.name}</div>
            <div className="mt-1 text-xs text-mutedfg">{engagement.inScope.length} in scope · {engagement.authorizedFrom ? new Date(engagement.authorizedFrom).toLocaleDateString() : 'Open start'} → {engagement.authorizedTo ? new Date(engagement.authorizedTo).toLocaleDateString() : 'Open end'}</div>
          </div>
          <StatusPill status={engagement.status} />
        </Link>
      ))}
    </Card>
  )
}

export function AssetFindings() {
  const context = useAssetContext()
  if (!context.findings.length) return <EmptyState icon={Bug} title="No current findings" hint="This is not a clean result unless Coverage is complete and current." />
  return (
    <Card title="Current findings" bodyClass="divide-y divide-border p-0">
      {context.findings.map((row) => (
        <Link key={`${row.external ? 'external' : 'internal'}-${row.finding.id}`} to={row.external ? `/engagements/${row.engagementId}` : `/engagements/${row.engagementId}#finding-${encodeURIComponent(row.finding.id)}`} className="flex items-start justify-between gap-4 p-4 transition-colors hover:bg-elevated sm:px-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{row.finding.title}</span>
              {row.external && <Pill>External · {row.provenance?.toolName || 'unknown tool'}</Pill>}
              {row.suppressedByTool && <Pill>Suppressed by tool</Pill>}
            </div>
            <div className="mt-1 text-xs text-mutedfg">{row.engagementName} · {row.external ? 'external result' : row.finding.status} · reachability {row.reachability.state} ({row.reachability.tier}){row.reachability.status ? ` · ${row.reachability.status}` : ''}</div>
            {row.external && row.provenance && <div className="mt-1 font-mono text-[11px] text-subtlefg">{row.provenance.toolName} {row.provenance.toolVersion} · {row.provenance.ruleId} · {row.provenance.sourceDigest}</div>}
          </div>
          <SevBadge sev={row.finding.severity} />
        </Link>
      ))}
    </Card>
  )
}

const COVERAGE_STYLE: Record<AssetCoverageVerdict, string> = {
  covered: 'bg-accent/10 text-accent ring-accent/30',
  stale: 'bg-info/10 text-info ring-info/30',
  not_assessed: 'bg-muted text-mutedfg ring-border',
  unknown: 'bg-muted text-mutedfg ring-border',
  excluded: 'bg-medium/10 text-medium ring-medium/30',
  failed: 'bg-critical/10 text-critical ring-critical/30',
  partial: 'bg-high/10 text-high ring-high/30',
  unauthorized: 'bg-critical/10 text-critical ring-critical/30',
}

function CoverageBadge({ verdict }: { verdict: AssetCoverageVerdict }) {
  return <span className={cn('inline-flex rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset', COVERAGE_STYLE[verdict])}>{verdict.replace('_', ' ')}</span>
}

export function AssetCoverageView() {
  const context = useAssetContext()
  if (!context.coverage.rows.length) return <EmptyState icon={ListChecks} title="No expected components" hint="Link Projects or technical assets to establish the coverage denominator." />
  return (
    <div className="space-y-4">
      <Card title={`Coverage · ${context.coverage.freshnessTargetDays} day freshness target`}>
        <div className="flex flex-wrap gap-3">
          {Object.entries(context.coverage.counts).map(([verdict, count]) => <span key={verdict} className="inline-flex items-center gap-2"><CoverageBadge verdict={verdict as AssetCoverageVerdict} /><span className="text-sm tabular-nums text-mutedfg">{count}</span></span>)}
        </div>
      </Card>
      <Card title="Expected components" bodyClass="divide-y divide-border p-0">
        {context.coverage.rows.map((row) => (
          <div key={`${row.kind}-${row.componentId}`} className="flex flex-wrap items-center justify-between gap-3 p-4 sm:px-5">
            <div>
              <div className="font-mono text-sm">{row.name || row.componentId}</div>
              <div className="mt-1 text-xs text-mutedfg">{row.kind} · {row.lastAssessed ? `last assessed ${new Date(row.lastAssessed).toLocaleString()}` : 'never assessed'}</div>
            </div>
            <CoverageBadge verdict={row.verdict} />
          </div>
        ))}
      </Card>
    </div>
  )
}

export function AssetHistory() {
  const context = useAssetContext()
  if (!context.history.length) return <EmptyState icon={History} title="No assessment history" hint="Assigned Engagements and retests will appear here without rewriting historical records." />
  return (
    <div className="space-y-3">
      {context.history.map((history) => (
        <Link key={history.engagementId} to={`/engagements/${history.engagementId}`} className="flex items-start gap-4 rounded-xl border border-border bg-card p-4 shadow-sm transition-colors hover:border-brand/40">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand/10 text-branddim"><CalendarClock className="size-4" /></span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium">{history.name}</span><StatusPill status={history.status} /></div>
            <p className="mt-1 text-xs text-mutedfg">{history.scopeCount} scope targets · {history.findingCount} findings · {history.retestCount} retests · updated {new Date(history.updatedAt).toLocaleString()}</p>
          </div>
        </Link>
      ))}
    </div>
  )
}
