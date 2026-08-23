import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Box,
  Calendar,
  CheckDone01,
  ClockRewind,
  FolderCode,
  Plus,
  Server04,
  Target04,
  User01,
  Virus,
  XClose,
} from '@untitledui/icons'
import { type ComponentType, useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useOutletContext, useParams } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, SevBadge, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api, ApiError } from '../../lib/api'
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
} from '../../lib/types'
import { PostureBadge } from './Assets'
import { StatusPill } from '../Engagements'

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
  const [notFound, setNotFound] = useState(false)

  const { data: fetchedData, error, refetch } = useFetch<Omit<Context, 'reload'>>(
    () => Promise.all([
      api.getBusinessAsset(key),
      api.businessAssetProjects(key),
      api.businessAssetTechnicalAssets(key),
      api.businessAssetEngagements(key),
      api.businessAssetFindings(key),
      api.businessAssetCoverage(key),
      api.businessAssetPosture(key),
      api.businessAssetHistory(key),
    ]).then(([asset, projects, technical, engagements, findings, coverage, posture, history]) => {
      setNotFound(false)
      return { asset, projects, technical, engagements, findings, coverage, posture, history }
    }).catch((nextError) => {
      if (nextError instanceof ApiError && nextError.status === 404) {
        setNotFound(true)
        return null as never
      }
      throw nextError
    }),
    { deps: [key] },
  )

  const context: Context | null = fetchedData ? { ...fetchedData, reload: refetch } : null

  if (error && !notFound) return <div className="mx-auto max-w-6xl"><ErrorState message={error} /></div>
  if (notFound) return <EmptyState icon={Box} title="Asset not found" hint="It may not exist or belongs to another tenant." />
  if (!context) return <Spinner label="Loading Asset…" />

  const data = context

  const retired = data.asset.lifecycle === 'retired'
  const componentCount = data.projects.length + data.technical.length
  const coveragePercent = data.coverage.rows.length
    ? Math.round(((data.coverage.counts.covered ?? 0) / data.coverage.rows.length) * 100)
    : 0

  return (
    <div className="mx-auto max-w-[1480px] animate-fade-in">
      <Link to="/assets" className="mb-4 inline-flex items-center gap-1.5 text-sm font-medium text-tertiary hover:text-primary">
        <ArrowLeft className="size-4" />Asset inventory
      </Link>

      <header className="mb-5 overflow-hidden rounded-xl border border-secondary bg-primary shadow-xs">
        <div className="bg-hero flex flex-wrap items-start justify-between gap-5 p-5 sm:p-7">
          <div className="flex min-w-0 gap-4">
            <span className="hidden size-12 shrink-0 items-center justify-center rounded-xl bg-brand/10 text-brand-secondary sm:flex">
              <Box className="size-6" />
            </span>
            <div className="min-w-0">
              <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-brand-secondary">Asset workspace</p>
              <h1 className="truncate text-3xl font-bold tracking-tight sm:text-4xl">{data.asset.name}</h1>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                <span className="font-mono text-quaternary">{data.asset.key}</span>
                {data.asset.description && (
                  <>
                    <span className="text-quaternary">·</span>
                    <span className="text-tertiary">{data.asset.description}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-x-6 gap-y-3 rounded-xl border border-secondary/70 bg-primary/70 p-4 shadow-xs backdrop-blur-xs text-sm">
            <ProfileItem icon={User01} label="Owner" value={data.asset.owner} />
            <ProfileItem icon={Box} label="Type" value={data.asset.type.replace('_', ' ')} />
            <ProfileItem icon={AlertTriangle} label="Criticality" value={data.asset.criticality} />
            <ProfileItem icon={Activity} label="Lifecycle" value={data.asset.lifecycle} />
          </div>
        </div>
      </header>

      {retired && (
        <div className="mb-5 flex items-start gap-3 rounded-xl border border-high/30 bg-high/10 p-4 text-sm text-high">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>This Asset is retired and remains readable for history. Membership and assignment changes are disabled.</span>
        </div>
      )}

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <DetailStat icon={Target04} label="Engagements" value={data.engagements.length} tone="brand" />
        <DetailStat icon={Box} label="Components" value={componentCount} tone="info" />
        <DetailStat icon={Virus} label="Current findings" value={data.findings.length} tone={data.findings.length ? 'critical' : 'muted'} />
        <DetailStat icon={CheckDone01} label="Coverage" value={`${coveragePercent}%`} tone={coveragePercent === 100 ? 'accent' : 'brand'} />
      </div>

      <nav className="mb-6 flex gap-1 overflow-x-auto rounded-xl border border-secondary bg-primary p-1.5 shadow-xs whitespace-nowrap" aria-label="Asset views">
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
  return `/engagements/new?${new URLSearchParams({ assetId }).toString()}`
}

function ProfileItem({ icon: Icon, label, value }: { icon: ComponentType<{ className?: string }>; label: string; value: string }) {
  return (
    <span className="flex items-center gap-2 text-tertiary">
      <Icon className="size-4 text-quaternary" />
      <span className="text-xs text-quaternary">{label}</span>
      <span className="font-medium capitalize text-primary">{value}</span>
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
        isActive ? 'bg-brand/10 text-brand-secondary' : 'text-tertiary hover:bg-secondary hover:text-primary',
      )}
    >
      {children}
    </NavLink>
  )
}

function DetailStat({ icon: Icon, label, value, tone = 'muted' }: { icon: ComponentType<{ className?: string }>; label: string; value: number | string; tone?: 'muted' | 'critical' | 'accent' | 'brand' | 'info' }) {
  const iconTone = {
    muted: 'bg-secondary text-tertiary',
    critical: 'bg-critical/10 text-critical',
    accent: 'bg-accent/10 text-accent',
    brand: 'bg-brand/10 text-brand-secondary',
    info: 'bg-info/10 text-info',
  }[tone]
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-2xl font-bold tabular-nums sm:text-3xl">{value}</div>
          <div className="mt-1 text-xs font-medium text-tertiary sm:text-sm">{label}</div>
        </div>
        <span className={cn('flex size-9 items-center justify-center rounded-lg', iconTone)}><Icon className="size-4" /></span>
      </div>
    </div>
  )
}

function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 3600_000) return `${Math.max(1, Math.round(diff / 60_000))}m ago`
  if (diff < 86400_000) return `${Math.round(diff / 3600_000)}h ago`
  return `${Math.round(diff / 86400_000)}d ago`
}

export function AssetOverview() {
  const context = useAssetContext()
  const [showEditor, setShowEditor] = useState(false)

  const coveragePercent = context.coverage.rows.length
    ? Math.round(((context.coverage.counts.covered ?? 0) / context.coverage.rows.length) * 100)
    : 0

  return (
    <div className="space-y-5">
      {/* Zone 1: Stat strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {/* Posture card */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="text-xs font-semibold text-tertiary">Posture</div>
          <div className="mt-2 flex items-center gap-2">
            <PostureBadge rating={context.posture.rating} />
          </div>
          <div className="mt-2 truncate text-xs text-quaternary" title={context.posture.explanation}>
            {context.posture.explanation}
          </div>
        </div>

        {/* Severity cards from findingCounts */}
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
          <div key={sev} className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
            <div className="text-xs font-semibold capitalize text-tertiary">{sev}</div>
            <div className="mt-2 text-2xl font-bold tabular-nums text-primary sm:text-3xl">
              {context.posture.findingCounts[sev] ?? 0}
            </div>
            <div className="mt-1 text-xs text-quaternary">findings</div>
          </div>
        ))}

        {/* Coverage card from coverageCounts */}
        <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
          <div className="text-xs font-semibold text-tertiary">Coverage</div>
          <div className="mt-2 text-2xl font-bold tabular-nums text-primary sm:text-3xl">
            {coveragePercent}%
          </div>
          <div className="mt-1 truncate text-xs text-quaternary">
            {context.coverage.counts.stale ?? 0} stale · {context.coverage.counts.not_assessed ?? 0} unassessed
          </div>
        </div>
      </div>

      {/* Zone 2 + 3: Profile + Recent engagements */}
      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
        {/* Zone 2: Read-only profile */}
        <Card
          title="Asset profile"
          actions={
            <Button
              variant="ghost"
              onClick={() => setShowEditor((v) => !v)}
              className="text-xs font-semibold text-brand-secondary hover:text-brand-primary"
            >
              ✎ {showEditor ? 'Hide editor' : 'Edit'}
            </Button>
          }
        >
          <dl className="grid grid-cols-1 gap-x-6 gap-y-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs font-semibold text-tertiary">Name</dt>
              <dd className="mt-1 font-medium text-primary">{context.asset.name}</dd>
            </div>
            <div>
              <dt className="text-xs font-semibold text-tertiary">Owner</dt>
              <dd className="mt-1 font-medium text-primary">{context.asset.owner}</dd>
            </div>
            <div>
              <dt className="text-xs font-semibold text-tertiary">Type</dt>
              <dd className="mt-1 font-medium capitalize text-primary">{context.asset.type.replace('_', ' ')}</dd>
            </div>
            <div>
              <dt className="text-xs font-semibold text-tertiary">Criticality</dt>
              <dd className="mt-1 font-medium capitalize text-primary">{context.asset.criticality}</dd>
            </div>
            <div>
              <dt className="text-xs font-semibold text-tertiary">Description</dt>
              <dd className="mt-1 text-primary">{context.asset.description || '—'}</dd>
            </div>
            <div>
              <dt className="text-xs font-semibold text-tertiary">Lifecycle / Version</dt>
              <dd className="mt-1 flex items-center gap-2">
                <Pill>{context.asset.lifecycle}</Pill>
                <Pill>v{context.asset.version}</Pill>
              </dd>
            </div>
          </dl>
        </Card>

        {/* Zone 3: Recent engagements */}
        <Card title="Recent engagements">
          {context.history.length === 0 ? (
            <p className="text-sm text-tertiary">No engagement history.</p>
          ) : (
            <ul className="divide-y divide-secondary">
              {context.history.slice(0, 3).map((h) => (
                <li key={h.engagementId} className="py-3 first:pt-0 last:pb-0">
                  <Link to={`/engagements/${h.engagementId}`} className="group block">
                    <div className="font-medium text-primary group-hover:text-brand-secondary">
                      {h.name}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-tertiary">
                      <span className="font-medium capitalize text-secondary">{h.status}</span>
                      <span>·</span>
                      <span>{h.findingCount} findings</span>
                      <span>·</span>
                      <span>{h.retestCount} retests</span>
                      {h.updatedAt && (
                        <>
                          <span>·</span>
                          <span>Updated {formatRelative(h.updatedAt)}</span>
                        </>
                      )}
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {/* Zone 4: Collapsible editor */}
      {showEditor && <AssetEditor key={context.asset.version} />}
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
            <Button variant="secondary-color" disabled={saving} onClick={() => save(next[context.asset.lifecycle])}>
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
        <div className="space-y-1.5">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Lifecycle / version</div>
          <div className="flex h-10 items-center gap-2">
            <Pill>{context.asset.lifecycle}</Pill>
            <Pill>v{context.asset.version}</Pill>
          </div>
        </div>
      </div>
      {error && <div className="mt-4"><ErrorState message={error} /></div>}
    </Card>
  )
}

function MembershipEditor({ title, icon: Icon, items, options, technical = false }: { title: string; icon: ComponentType<{ className?: string }>; items: AssetMembership[]; options: { value: string; label: string }[]; technical?: boolean }) {
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
          <div key={`${row.componentId}-${index}`} className="grid items-center gap-3 sm:grid-cols-[minmax(0,1.2fr)_minmax(140px,0.6fr)_minmax(0,1.2fr)_auto]">
            <Select
              ariaLabel={`${title} component`}
              placeholder="Select component"
              disabled={retired}
              value={row.componentId}
              onValueChange={(componentId) => setRows((value) => value.map((item, itemIndex) => itemIndex === index ? { ...item, componentId } : item))}
              options={componentOptions}
              className="h-10 w-full"
            />
            <Select
              ariaLabel={`${title} role`}
              disabled={retired}
              value={row.role}
              onValueChange={(role) => setRows((value) => value.map((item, itemIndex) => itemIndex === index ? { ...item, role: role as AssetMembership['role'] } : item))}
              options={[
                { value: 'primary', label: 'Primary' },
                { value: 'supporting', label: 'Supporting' },
                { value: 'dependency', label: 'Dependency' },
              ]}
              className="h-10 w-full"
            />
            <Input
              aria-label={`${title} provenance`}
              placeholder="Provenance (e.g. manual, CI/CD)"
              disabled={retired}
              value={row.provenance}
              onChange={(event) => setRows((value) => value.map((item, itemIndex) => itemIndex === index ? { ...item, provenance: event.target.value } : item))}
              className="h-10 w-full"
            />
            <button
              type="button"
              disabled={retired}
              onClick={() => setRows((value) => value.filter((_, itemIndex) => itemIndex !== index))}
              className="flex size-10 shrink-0 items-center justify-center rounded-lg text-tertiary transition-colors hover:bg-secondary hover:text-primary disabled:opacity-40"
              aria-label="Remove component"
            >
              <XClose className="size-4" />
            </button>
          </div>
        ))}
        {rows.length === 0 && (
          <div className="flex items-center gap-2 rounded-lg bg-secondary p-4 text-sm text-tertiary">
            <Icon className="size-4" />No components linked.
          </div>
        )}
        <div>
          <Button
            variant="secondary-color"
            disabled={retired || options.length === 0}
            onClick={() => setRows((value) => [...value, { componentId: '', role: 'supporting', provenance: 'manual' }])}
          >
            <Plus className="size-4" />Add component
          </Button>
        </div>
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
      <MembershipEditor title="Projects / repositories" icon={FolderCode} items={context.projects} options={options.projects} />
      <MembershipEditor title="Technical / fleet assets" icon={Server04} items={context.technical} options={options.technical} technical />
    </div>
  )
}

export function AssetEngagements() {
  const context = useAssetContext()
  const action = context.asset.lifecycle !== 'retired' ? (
    <Link to={newEngagementPath(context.asset.id)} className="inline-flex items-center gap-2 text-sm font-semibold text-brand-secondary hover:underline">
      <Plus className="size-4" />New Engagement
    </Link>
  ) : undefined

  if (!context.engagements.length) {
    return <EmptyState icon={Target04} title="No Engagements assigned" hint="Create an Engagement from this Asset to preselect the relationship." action={action} />
  }
  return (
    <Card title="Assigned Engagements" actions={action} bodyClass="divide-y divide-secondary p-0">
      {context.engagements.map((engagement) => (
        <Link key={engagement.id} to={`/engagements/${engagement.id}`} className="flex items-center justify-between gap-3 p-4 transition-colors hover:bg-secondary sm:px-5">
          <div>
            <div className="font-medium text-primary">{engagement.name}</div>
            <div className="mt-0.5 text-xs text-tertiary">{engagement.inScope.length} in scope · {engagement.authorizedFrom ? new Date(engagement.authorizedFrom).toLocaleDateString() : 'Open start'} → {engagement.authorizedTo ? new Date(engagement.authorizedTo).toLocaleDateString() : 'Open end'}</div>
          </div>
          <div className="shrink-0">
            <StatusPill status={engagement.status} size="md" />
          </div>
        </Link>
      ))}
    </Card>
  )
}

export function AssetFindings() {
  const context = useAssetContext()
  const PAGE_SIZE = 25
  const [severity, setSeverity] = useState('all')
  const [page, setPage] = useState(0)

  if (!context.findings.length) {
    return <EmptyState icon={Virus} title="No current findings" hint="This is not a clean result unless Coverage is complete and current." />
  }

  const filtered = severity === 'all'
    ? context.findings
    : context.findings.filter((r) => r.finding.severity.toLowerCase() === severity)

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <Card title="Current findings" bodyClass="p-0">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-secondary px-4 py-3 sm:px-5">
        <div className="flex items-center gap-1 rounded-lg bg-secondary p-1">
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => {
                setSeverity(sev)
                setPage(0)
              }}
              className={cn(
                'rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                severity === sev ? 'bg-primary text-primary shadow-xs' : 'text-tertiary hover:text-primary',
              )}
            >
              {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
        <span className="text-xs text-tertiary">{filtered.length} finding{filtered.length === 1 ? '' : 's'}</span>
      </div>

      {filtered.length === 0 ? (
        <div className="p-8 text-center text-sm text-tertiary">
          No findings match this severity filter.
        </div>
      ) : (
        <div className="divide-y divide-secondary">
          {visible.map((row) => (
            <Link
              key={`${row.external ? 'external' : 'internal'}-${row.finding.id}`}
              to={row.external ? `/engagements/${row.engagementId}` : `/engagements/${row.engagementId}#finding-${encodeURIComponent(row.finding.id)}`}
              className="flex items-start justify-between gap-4 p-4 transition-colors hover:bg-secondary sm:px-5"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-primary">{row.finding.title}</span>
                  {row.external && <Pill>External · {row.provenance?.toolName || 'unknown tool'}</Pill>}
                  {row.suppressedByTool && <Pill>Suppressed by tool</Pill>}
                </div>
                <div className="mt-1 text-xs text-tertiary">
                  {row.engagementName} · {row.external ? 'external result' : row.finding.status} · reachability {row.reachability.state} ({row.reachability.tier}){row.reachability.status ? ` · ${row.reachability.status}` : ''}
                </div>
                {row.external && row.provenance && (
                  <div className="mt-1 font-mono text-[11px] text-quaternary">
                    {row.provenance.toolName} {row.provenance.toolVersion} · {row.provenance.ruleId} · {row.provenance.sourceDigest}
                  </div>
                )}
              </div>
              <SevBadge sev={row.finding.severity} />
            </Link>
          ))}
        </div>
      )}

      {filtered.length > PAGE_SIZE && (
        <div className="flex items-center justify-between border-t border-secondary px-5 py-3 text-sm text-tertiary">
          <span>Page {page + 1} of {pageCount}</span>
          <div className="flex gap-2">
            <Button variant="secondary" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Previous
            </Button>
            <Button variant="secondary" disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>
              Next
            </Button>
          </div>
        </div>
      )}
    </Card>
  )
}

const COVERAGE_STYLE: Record<AssetCoverageVerdict, string> = {
  covered: 'bg-accent/10 text-accent ring-accent/30',
  stale: 'bg-info/10 text-info ring-info/30',
  not_assessed: 'bg-secondary text-tertiary ring-secondary',
  unknown: 'bg-secondary text-tertiary ring-secondary',
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
  if (!context.coverage.rows.length) return <EmptyState icon={CheckDone01} title="No expected components" hint="Link Projects or technical assets to establish the coverage denominator." />
  return (
    <Card
      title={`Coverage · ${context.coverage.freshnessTargetDays}-day freshness`}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {Object.entries(context.coverage.counts).map(([verdict, count]) => (
            <span key={verdict} className="inline-flex items-center gap-1.5">
              <CoverageBadge verdict={verdict as AssetCoverageVerdict} />
              <span className="text-xs tabular-nums text-tertiary">{count}</span>
            </span>
          ))}
        </div>
      }
      bodyClass="divide-y divide-secondary p-0"
    >
      {context.coverage.rows.map((row) => (
        <div key={`${row.kind}-${row.componentId}`} className="flex items-center justify-between gap-3 px-5 py-2.5">
          <div className="min-w-0">
            <span className="text-sm font-medium text-primary">{row.name || row.componentId}</span>
            <span className="ml-2 text-xs text-tertiary">
              {row.kind} · {row.lastAssessed ? new Date(row.lastAssessed).toLocaleDateString() : 'never assessed'}
            </span>
          </div>
          <CoverageBadge verdict={row.verdict} />
        </div>
      ))}
    </Card>
  )
}

export function AssetHistory() {
  const context = useAssetContext()
  if (!context.history.length) return <EmptyState icon={ClockRewind} title="No assessment history" hint="Assigned Engagements and retests will appear here without rewriting historical records." />
  return (
    <div className="space-y-3">
      {context.history.map((history) => (
        <Link
          key={history.engagementId}
          to={`/engagements/${history.engagementId}`}
          className="flex items-center justify-between gap-4 rounded-xl border border-secondary bg-primary p-4 shadow-xs transition-colors hover:border-brand/40"
        >
          <div className="flex min-w-0 items-center gap-3.5">
            <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-brand/10 text-brand-secondary">
              <Calendar className="size-5" />
            </span>
            <div className="min-w-0">
              <div className="font-medium text-primary">{history.name}</div>
              <p className="mt-0.5 text-xs text-tertiary">
                {history.scopeCount} scope targets · {history.findingCount} findings · {history.retestCount} retests · updated {new Date(history.updatedAt).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="shrink-0">
            <StatusPill status={history.status} size="md" />
          </div>
        </Link>
      ))}
    </div>
  )
}
