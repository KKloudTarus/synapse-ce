import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Boxes,
  CircleDot,
  Layers3,
  Plus,
  Search,
  ShieldCheck,
  X,
  type LucideIcon,
} from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../components/ui'
import { api } from '../lib/api'
import { useFetch } from '../hooks'
import type {
  BusinessAsset,
  BusinessAssetCriticality,
  BusinessAssetInput,
  BusinessAssetPage,
  BusinessAssetType,
} from '../lib/types'

const PAGE_SIZE = 24
const TYPES = [
  { value: '', label: 'All types' },
  { value: 'product', label: 'Product' },
  { value: 'application', label: 'Application' },
  { value: 'system', label: 'System' },
  { value: 'business_service', label: 'Business service' },
]
const CRITICALITIES = [
  { value: '', label: 'All criticalities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]
const LIFECYCLES = [
  { value: '', label: 'All lifecycle states' },
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
  const [type, setType] = useState('')
  const [criticality, setCriticality] = useState('')
  const [lifecycle, setLifecycle] = useState('')

  const { data: result, error } = useFetch<BusinessAssetPage>(
    (_signal) => {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) })
      if (query.trim()) params.set('q', query.trim())
      if (type) params.set('type', type)
      if (criticality) params.set('criticality', criticality)
      if (lifecycle) params.set('lifecycle', lifecycle)
      return api.listBusinessAssets(params.toString())
    },
    { deps: [criticality, lifecycle, page, query, revision, type] },
  )

  const hasFilters = Boolean(query.trim() || type || criticality || lifecycle)
  const pageCount = result ? Math.max(1, Math.ceil(result.total / PAGE_SIZE)) : 1
  const visible = result?.items ?? []
  const updateFilter = (setter: (value: string) => void) => (value: string) => {
    setPage(0)
    setter(value)
  }

  return (
    <div className="mx-auto max-w-[1480px] animate-fade-in">
      <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-branddim">Asset management</p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Security asset inventory</h1>
          <p className="mt-2 max-w-3xl text-sm text-mutedfg sm:text-base">
            Track products, applications, systems, and business services with their Engagement coverage and security posture.
          </p>
        </div>
        <Button variant="brand" onClick={() => setCreating((value) => !value)}>
          {creating ? <><X className="size-4" />Cancel</> : <><Plus className="size-4" />New Asset</>}
        </Button>
      </header>

      {creating && (
        <div className="mb-6">
          <CreateAssetForm onCreated={() => { setCreating(false); setRevision((value) => value + 1) }} />
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SummaryCard icon={Layers3} label="Total assets" value={result?.total ?? '—'} hint="Across this inventory" />
        <SummaryCard icon={AlertTriangle} label="Critical" value={visible.filter((asset) => asset.criticality === 'critical').length} hint="On current page" tone="critical" />
        <SummaryCard icon={Activity} label="Active" value={visible.filter((asset) => asset.lifecycle === 'active').length} hint="On current page" tone="accent" />
        <SummaryCard icon={ShieldCheck} label="Needs attention" value={visible.filter((asset) => !['good', 'unknown'].includes(asset.posture ?? 'unknown')).length} hint="On current page" tone="brand" />
      </div>

      <Card className="overflow-hidden" bodyClass="p-0">
        <div className="border-b border-border p-4 sm:p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-semibold">Asset inventory</h2>
              <p className="mt-0.5 text-xs text-subtlefg">Filter and open an Asset to manage its complete security workspace.</p>
            </div>
            {result && <span className="text-sm text-mutedfg">{result.total} result{result.total === 1 ? '' : 's'}</span>}
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-[minmax(260px,1.5fr)_1fr_1fr_1fr]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-3 size-4 text-subtlefg" />
              <Input
                aria-label="Search assets"
                value={query}
                onChange={(event) => updateFilter(setQuery)(event.target.value)}
                placeholder="Search name, key, or owner"
                className="pl-9"
              />
            </div>
            <Select value={type} onValueChange={updateFilter(setType)} options={TYPES} />
            <Select value={criticality} onValueChange={updateFilter(setCriticality)} options={CRITICALITIES} />
            <Select value={lifecycle} onValueChange={updateFilter(setLifecycle)} options={LIFECYCLES} />
          </div>
        </div>

        {error && <div className="p-5"><ErrorState message={error} /></div>}
        {!result && !error && <Spinner label="Loading Assets…" />}
        {result && result.items.length === 0 && (
          <div className="p-5">
            <EmptyState
              icon={Boxes}
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
                <thead className="bg-elevated text-[11px] font-semibold uppercase tracking-wider text-subtlefg">
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
                <tbody className="divide-y divide-border">
                  {result.items.map((asset) => <AssetRow key={asset.id} asset={asset} />)}
                </tbody>
              </table>
            </div>
            <div className="divide-y divide-border md:hidden">
              {result.items.map((asset) => <AssetMobileRow key={asset.id} asset={asset} />)}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-5 py-4 text-sm text-mutedfg">
              <span>Page {page + 1} of {pageCount}</span>
              <div className="flex gap-2">
                <Button variant="secondary" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</Button>
                <Button variant="secondary" disabled={(page + 1) * PAGE_SIZE >= result.total} onClick={() => setPage((value) => value + 1)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  )
}

function SummaryCard({ icon: Icon, label, value, hint, tone = 'muted' }: { icon: LucideIcon; label: string; value: number | string; hint: string; tone?: 'muted' | 'critical' | 'accent' | 'brand' }) {
  const iconTone = {
    muted: 'bg-muted text-mutedfg',
    critical: 'bg-critical/10 text-critical',
    accent: 'bg-accent/10 text-accent',
    brand: 'bg-brand/10 text-branddim',
  }[tone]
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-2xl font-bold tabular-nums sm:text-3xl">{value}</div>
          <div className="mt-1 text-sm font-medium">{label}</div>
        </div>
        <span className={cn('flex size-9 items-center justify-center rounded-lg', iconTone)}><Icon className="size-4" /></span>
      </div>
      <div className="mt-3 text-xs text-subtlefg">{hint}</div>
    </div>
  )
}

function AssetRow({ asset }: { asset: BusinessAsset }) {
  return (
    <tr className="group transition-colors hover:bg-elevated/70">
      <td className="px-5 py-4">
        <Link to={`/assets/${encodeURIComponent(asset.id)}`} className="block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50">
          <div className="font-semibold text-foreground group-hover:text-branddim">{asset.name}</div>
          <div className="mt-1 font-mono text-xs text-subtlefg">{asset.key}</div>
        </Link>
      </td>
      <td className="px-4 py-4"><Pill>{asset.type.replace('_', ' ')}</Pill></td>
      <td className="px-4 py-4"><CriticalityBadge value={asset.criticality} /></td>
      <td className="max-w-48 truncate px-4 py-4 text-mutedfg">{asset.owner}</td>
      <td className="px-4 py-4"><LifecycleBadge value={asset.lifecycle} /></td>
      <td className="px-4 py-4"><PostureBadge rating={asset.posture ?? 'unknown'} /></td>
      <td className="whitespace-nowrap px-4 py-4 text-mutedfg">{formatDate(asset.updatedAt)}</td>
      <td className="px-4 py-4">
        <Link to={`/assets/${encodeURIComponent(asset.id)}`} aria-label={`Open ${asset.name}`} className="inline-flex size-8 items-center justify-center rounded-lg text-subtlefg hover:bg-raised hover:text-branddim">
          <ArrowUpRight className="size-4" />
        </Link>
      </td>
    </tr>
  )
}

function AssetMobileRow({ asset }: { asset: BusinessAsset }) {
  return (
    <Link to={`/assets/${encodeURIComponent(asset.id)}`} className="block p-4 transition-colors hover:bg-elevated">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate font-semibold">{asset.name}</h2>
          <p className="mt-1 truncate font-mono text-xs text-subtlefg">{asset.key}</p>
        </div>
        <PostureBadge rating={asset.posture ?? 'unknown'} />
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <CriticalityBadge value={asset.criticality} />
        <LifecycleBadge value={asset.lifecycle} />
        <Pill>{asset.type.replace('_', ' ')}</Pill>
      </div>
      <p className="mt-3 text-xs text-mutedfg">Owner · {asset.owner}</p>
    </Link>
  )
}

function CriticalityBadge({ value }: { value: BusinessAssetCriticality }) {
  const style = value === 'critical' ? 'bg-critical/10 text-critical ring-critical/25' : value === 'high' ? 'bg-high/10 text-high ring-high/25' : value === 'medium' ? 'bg-medium/10 text-medium ring-medium/25' : 'bg-accent/10 text-accent ring-accent/25'
  return <span className={cn('inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset', style)}><CircleDot className="size-3" />{value}</span>
}

function LifecycleBadge({ value }: { value: BusinessAsset['lifecycle'] }) {
  const style = value === 'active' ? 'bg-accent/10 text-accent ring-accent/25' : value === 'decommissioning' ? 'bg-high/10 text-high ring-high/25' : 'bg-muted text-mutedfg ring-border'
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
          : 'bg-muted text-mutedfg ring-border'
  return <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset', style)}><ShieldCheck className="size-3" />{rating.replace('_', ' ')}</span>
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

  async function submit(event: React.FormEvent) {
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
      navigate(`/assets/${encodeURIComponent(asset.id)}`)
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
