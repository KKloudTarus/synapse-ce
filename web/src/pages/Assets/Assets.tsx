import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Cube01,
  LayersThree01,
  Plus,
  SearchLg,
  ShieldTick,
  XClose,
} from '@untitledui/icons'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { PaginationCardDefault } from '../../components/application/pagination/pagination'
import { api } from '../../lib/api'
import { useFetch } from '../../hooks'
import type {
  BusinessAsset,
  BusinessAssetCriticality,
  BusinessAssetInput,
  BusinessAssetPage,
  BusinessAssetType,
} from '../../lib/types'

const PAGE_SIZE = 5
const TYPES = [
  { value: 'all', label: 'All types' },
  { value: 'product', label: 'Product' },
  { value: 'application', label: 'Application' },
  { value: 'system', label: 'System' },
  { value: 'business_service', label: 'Business service' },
]
const CRITICALITIES = [
  { value: 'all', label: 'All criticalities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]
const LIFECYCLES = [
  { value: 'all', label: 'All lifecycle states' },
  { value: 'draft', label: 'Draft' },
  { value: 'active', label: 'Active' },
  { value: 'decommissioning', label: 'Decommissioning' },
  { value: 'retired', label: 'Retired' },
]

export function Assets() {
  const [page, setPage] = useState(0)
  const [creating, setCreating] = useState(false)
  const [revision, setRevision] = useState(0)
  const [query, setQuery] = useState('')
  const [type, setType] = useState('all')
  const [criticality, setCriticality] = useState('all')
  const [lifecycle, setLifecycle] = useState('all')

  const { data: result, error } = useFetch<BusinessAssetPage>(
    (_signal) => {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) })
      if (query.trim()) params.set('q', query.trim())
      if (type && type !== 'all') params.set('type', type)
      if (criticality && criticality !== 'all') params.set('criticality', criticality)
      if (lifecycle && lifecycle !== 'all') params.set('lifecycle', lifecycle)
      return api.listBusinessAssets(params.toString())
    },
    { deps: [criticality, lifecycle, page, query, revision, type] },
  )

  const hasFilters = Boolean(query.trim() || (type && type !== 'all') || (criticality && criticality !== 'all') || (lifecycle && lifecycle !== 'all'))
  const pageCount = result ? Math.max(1, Math.ceil(result.total / PAGE_SIZE)) : 1
  const visible = result?.items ?? []
  const updateFilter = (setter: (value: string) => void) => (value: string) => {
    setPage(0)
    setter(value)
  }

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Security Asset Inventory</h1>
          <p className="mt-1 text-sm text-secondary">
            Track assets, engagement coverage, and security posture
          </p>
        </div>
        <Button
          variant={creating ? 'secondary' : 'brand'}
          onClick={() => setCreating((value) => !value)}
          className={creating ? '!border-brand-solid !text-brand-secondary hover:!bg-brand-primary/10' : undefined}
        >
          {creating ? <><XClose className="size-4" />Cancel</> : <><Plus className="size-4" />New Asset</>}
        </Button>
      </header>

      {creating && (
        <div>
          <CreateAssetForm onCreated={() => { setCreating(false); setRevision((value) => value + 1) }} />
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SummaryCard icon={LayersThree01} label="Total assets" value={result?.total ?? '—'} hint="Across this inventory" tone="muted" />
        <SummaryCard icon={AlertTriangle} label="Critical" value={visible.filter((asset) => asset.criticality === 'critical').length} hint="On current page" tone="critical" />
        <SummaryCard icon={Activity} label="Active" value={visible.filter((asset) => asset.lifecycle === 'active').length} hint="On current page" tone="accent" />
        <SummaryCard icon={ShieldTick} label="Needs attention" value={visible.filter((asset) => !['good', 'unknown'].includes(asset.posture ?? 'unknown')).length} hint="On current page" tone="brand" />
      </div>

      <Card className="overflow-hidden" bodyClass="p-0">
        <div className="border-b border-secondary px-4 py-3.5 sm:px-5 sm:py-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-semibold text-primary">Asset inventory</h2>
              <p className="mt-0.5 text-xs text-tertiary">Filter and open an Asset to manage its complete security workspace.</p>
            </div>
            {result && <span className="text-sm text-tertiary">{result.total} result{result.total === 1 ? '' : 's'}</span>}
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="relative">
              <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
              <Input
                aria-label="Search assets"
                value={query}
                onChange={(event) => updateFilter(setQuery)(event.target.value)}
                placeholder="Search name, key, or owner"
                className="h-10 w-full pl-9"
              />
            </div>
            <Select value={type} onValueChange={updateFilter(setType)} options={TYPES} className="h-10 w-full" ariaLabel="Filter by type" />
            <Select value={criticality} onValueChange={updateFilter(setCriticality)} options={CRITICALITIES} className="h-10 w-full" ariaLabel="Filter by criticality" />
            <Select value={lifecycle} onValueChange={updateFilter(setLifecycle)} options={LIFECYCLES} className="h-10 w-full" ariaLabel="Filter by lifecycle" />
          </div>
        </div>

        {error && <div className="p-5"><ErrorState message={error} /></div>}
        {!result && !error && <Spinner label="Loading Assets…" />}
        {result && result.items.length === 0 && (
          <div className="p-5">
            <EmptyState
              icon={Cube01}
              title={hasFilters ? 'No matching Assets' : 'No Assets yet'}
              hint={hasFilters ? 'Adjust search or filters.' : 'Create a product, application, system, or business service to aggregate security posture.'}
              action={!hasFilters ? <Button variant="brand" onClick={() => setCreating(true)}><Plus className="size-4" />New Asset</Button> : undefined}
            />
          </div>
        )}
        {result && result.items.length > 0 && (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full min-w-[980px] border-collapse text-left text-sm">
                <thead className="border-b border-secondary bg-secondary/50 text-[11px] font-semibold uppercase tracking-wider text-tertiary">
                  <tr>
                    <th className="px-5 py-3">Asset</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Criticality</th>
                    <th className="px-4 py-3">Owner</th>
                    <th className="px-4 py-3">Lifecycle</th>
                    <th className="px-4 py-3">Posture</th>
                    <th className="px-4 py-3">Updated</th>
                    <th className="w-12 px-4 py-3"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-secondary">
                  {result.items.map((asset) => <AssetRow key={asset.id} asset={asset} />)}
                </tbody>
              </table>
            </div>
            <div className="divide-y divide-secondary md:hidden">
              {result.items.map((asset) => <AssetMobileRow key={asset.id} asset={asset} />)}
            </div>
            <PaginationCardDefault
              page={page + 1}
              total={pageCount}
              onPageChange={(nextPage) => setPage(nextPage - 1)}
            />
          </>
        )}
      </Card>
    </div>
  )
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  hint,
  tone = 'muted',
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: number | string
  hint: string
  tone?: 'muted' | 'critical' | 'accent' | 'brand'
}) {
  const iconColor = {
    muted: 'text-quaternary',
    critical: 'text-critical',
    accent: 'text-accent',
    brand: 'text-brand-secondary',
  }[tone]
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-secondary">{label}</div>
          <div className="mt-2 text-3xl font-bold tabular-nums text-primary sm:text-4xl">{value}</div>
        </div>
        <Icon className={cn('mt-0.5 size-5 shrink-0', iconColor)} />
      </div>
      <div className="mt-2 text-xs text-tertiary">{hint}</div>
    </div>
  )
}

function AssetRow({ asset }: { asset: BusinessAsset }) {
  return (
    <tr className="group transition-colors hover:bg-secondary/40">
      <td className="px-5 py-4">
        <Link to={`/assets/${encodeURIComponent(asset.key)}`} className="block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50">
          <div className="font-semibold text-primary group-hover:text-brand-secondary">{asset.name}</div>
          <div className="mt-1 font-mono text-xs text-tertiary">{asset.key}</div>
        </Link>
      </td>
      <td className="px-4 py-4"><Pill>{asset.type.replace('_', ' ')}</Pill></td>
      <td className="px-4 py-4"><CriticalityBadge value={asset.criticality} /></td>
      <td className="max-w-48 truncate px-4 py-4 text-tertiary">{asset.owner}</td>
      <td className="px-4 py-4"><LifecycleBadge value={asset.lifecycle} /></td>
      <td className="px-4 py-4"><PostureBadge rating={asset.posture ?? 'unknown'} /></td>
      <td className="whitespace-nowrap px-4 py-4 text-tertiary">{formatDate(asset.updatedAt)}</td>
      <td className="px-4 py-4">
        <Link to={`/assets/${encodeURIComponent(asset.key)}`} aria-label={`Open ${asset.name}`} className="inline-flex size-8 items-center justify-center rounded-lg text-quaternary hover:bg-secondary hover:text-primary">
          <ArrowUpRight className="size-4" />
        </Link>
      </td>
    </tr>
  )
}

function AssetMobileRow({ asset }: { asset: BusinessAsset }) {
  return (
    <Link to={`/assets/${encodeURIComponent(asset.key)}`} className="block p-4 transition-colors hover:bg-secondary/40">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate font-semibold text-primary">{asset.name}</h2>
          <p className="mt-1 truncate font-mono text-xs text-tertiary">{asset.key}</p>
        </div>
        <PostureBadge rating={asset.posture ?? 'unknown'} />
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <CriticalityBadge value={asset.criticality} />
        <LifecycleBadge value={asset.lifecycle} />
        <Pill>{asset.type.replace('_', ' ')}</Pill>
      </div>
      <p className="mt-3 text-xs text-tertiary">Owner · {asset.owner}</p>
    </Link>
  )
}

function CriticalityBadge({ value }: { value: BusinessAssetCriticality }) {
  const style = value === 'critical' ? 'bg-critical/10 text-critical ring-critical/25' : value === 'high' ? 'bg-high/10 text-high ring-high/25' : value === 'medium' ? 'bg-medium/10 text-medium ring-medium/25' : 'bg-accent/10 text-accent ring-accent/25'
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset', style)}>
      <span className="size-1.5 rounded-full bg-current" />
      {value}
    </span>
  )
}

function LifecycleBadge({ value }: { value: BusinessAsset['lifecycle'] }) {
  const style = value === 'active' ? 'bg-accent/10 text-accent ring-accent/25' : value === 'decommissioning' ? 'bg-high/10 text-high ring-high/25' : 'bg-secondary text-tertiary ring-secondary'
  return <span className={cn('inline-flex rounded-md px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset', style)}>{value}</span>
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleDateString() : '—'
}

export function PostureBadge({ rating }: { rating: string }) {
  const style = rating === 'good'
    ? 'bg-accent/10 text-accent ring-accent/30'
    : rating === 'critical'
      ? 'bg-critical/10 text-critical ring-critical/30'
      : rating === 'high_risk'
        ? 'bg-high/10 text-high ring-high/30'
        : rating === 'attention'
          ? 'bg-medium/10 text-medium ring-medium/30'
          : 'bg-secondary text-tertiary ring-secondary'
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset', style)}>
      <ShieldTick className="size-3" />
      {rating.replace('_', ' ')}
    </span>
  )
}

function CreateAssetForm({ onCreated }: { onCreated: () => void }) {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [description, setDescription] = useState('')
  const [type, setType] = useState<BusinessAssetType>('application')
  const [criticality, setCriticality] = useState<BusinessAssetCriticality>('medium')
  const [owner, setOwner] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!name.trim() || !key.trim() || !owner.trim()) {
      setError('Key, name, and owner are required.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const input: BusinessAssetInput = { key: key.trim(), name: name.trim(), description: description.trim(), type, criticality, owner: owner.trim() }
      const asset = await api.createBusinessAsset(input)
      onCreated()
      navigate(`/assets/${encodeURIComponent(asset.key)}`)
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Failed to create Asset')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card title="Create Asset" className="border-brand/25" bodyClass="p-5 sm:p-6">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          <Field label="Key"><Input value={key} onChange={(event) => setKey(event.target.value)} placeholder="mobile-banking" autoFocus /></Field>
          <Field label="Name"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Mobile Banking App" /></Field>
          <Field label="Owner"><Input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Mobile Platform Team" /></Field>
          <Field label="Type"><Select value={type} onValueChange={(value) => setType(value as BusinessAssetType)} options={TYPES.slice(1)} className="w-full" /></Field>
          <Field label="Criticality"><Select value={criticality} onValueChange={(value) => setCriticality(value as BusinessAssetCriticality)} options={CRITICALITIES.slice(1)} className="w-full" /></Field>
          <Field label="Description"><Input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Customer-facing mobile banking product" /></Field>
        </div>
        {error && <ErrorState message={error} />}
        <div className="flex justify-end"><Button variant="brand" type="submit" loading={submitting}>Create Asset</Button></div>
      </form>
    </Card>
  )
}
