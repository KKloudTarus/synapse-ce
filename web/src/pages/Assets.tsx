import { Boxes, Plus, Search, ShieldCheck, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Button, Card, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner, cn } from '../components/ui'
import { api } from '../lib/api'
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
  const [result, setResult] = useState<BusinessAssetPage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [revision, setRevision] = useState(0)
  const [query, setQuery] = useState('')
  const [type, setType] = useState('')
  const [criticality, setCriticality] = useState('')
  const [lifecycle, setLifecycle] = useState('')

  useEffect(() => {
    let active = true
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) })
    if (query.trim()) params.set('q', query.trim())
    if (type) params.set('type', type)
    if (criticality) params.set('criticality', criticality)
    if (lifecycle) params.set('lifecycle', lifecycle)
    setResult(null)
    setError(null)
    api
      .listBusinessAssets(params.toString())
      .then((next) => active && setResult(next))
      .catch((nextError) => active && setError(nextError instanceof Error ? nextError.message : 'Failed to load assets'))
    return () => {
      active = false
    }
  }, [criticality, lifecycle, page, query, revision, type])

  const hasFilters = Boolean(query.trim() || type || criticality || lifecycle)
  const pageCount = result ? Math.max(1, Math.ceil(result.total / PAGE_SIZE)) : 1
  const updateFilter = (setter: (value: string) => void) => (value: string) => {
    setPage(0)
    setter(value)
  }

  return (
    <div className="mx-auto max-w-6xl animate-fade-in">
      <header className="bg-hero mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border p-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Assets</h1>
          <p className="mt-1.5 max-w-2xl text-sm text-mutedfg">
            Manage product and application security posture across Engagements, repositories, services, and technical components.
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

      <Card className="mb-6" bodyClass="grid grid-cols-1 gap-3 md:grid-cols-4">
        <div className="relative md:col-span-1">
          <Search className="pointer-events-none absolute left-3 top-3 size-4 text-subtlefg" />
          <Input
            aria-label="Search assets"
            value={query}
            onChange={(event) => updateFilter(setQuery)(event.target.value)}
            placeholder="Search name, key, owner"
            className="pl-9"
          />
        </div>
        <Select value={type} onValueChange={updateFilter(setType)} options={TYPES} />
        <Select value={criticality} onValueChange={updateFilter(setCriticality)} options={CRITICALITIES} />
        <Select value={lifecycle} onValueChange={updateFilter(setLifecycle)} options={LIFECYCLES} />
      </Card>

      {error && <ErrorState message={error} />}
      {!result && !error && <Spinner label="Loading Assets…" />}
      {result && result.items.length === 0 && (
        <EmptyState
          icon={Boxes}
          title={hasFilters ? 'No matching Assets' : 'No Assets yet'}
          hint={hasFilters ? 'Adjust search or filters.' : 'Create a product, application, system, or business service to aggregate security posture.'}
          action={!hasFilters ? <Button variant="brand" onClick={() => setCreating(true)}><Plus className="size-4" />New Asset</Button> : undefined}
        />
      )}
      {result && result.items.length > 0 && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {result.items.map((asset) => <AssetCard key={asset.id} asset={asset} />)}
          </div>
          <div className="mt-6 flex flex-wrap items-center justify-between gap-3 text-sm text-mutedfg">
            <span>{result.total} Asset{result.total === 1 ? '' : 's'} · Page {page + 1} of {pageCount}</span>
            <div className="flex gap-2">
              <Button variant="secondary" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</Button>
              <Button variant="secondary" disabled={(page + 1) * PAGE_SIZE >= result.total} onClick={() => setPage((value) => value + 1)}>Next</Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function AssetCard({ asset }: { asset: BusinessAsset }) {
  return (
    <Link to={`/assets/${encodeURIComponent(asset.id)}`} className="lift card-sheen elev group block rounded-xl border border-border bg-card p-5 hover:border-brand/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate font-semibold">{asset.name}</h2>
          <p className="mt-1 truncate font-mono text-xs text-subtlefg">{asset.key}</p>
        </div>
        <PostureBadge rating={asset.posture ?? 'unknown'} />
      </div>
      <p className="mt-3 line-clamp-2 min-h-10 text-sm text-mutedfg">{asset.description || 'No description.'}</p>
      <div className="mt-4 flex flex-wrap gap-2">
        <Pill>{asset.type.replace('_', ' ')}</Pill>
        <Pill className={asset.criticality === 'critical' ? 'text-critical' : ''}>{asset.criticality}</Pill>
        <Pill>{asset.lifecycle}</Pill>
      </div>
      <p className="mt-4 text-xs text-subtlefg">Owner: <span className="text-mutedfg">{asset.owner}</span></p>
    </Link>
  )
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
  return <span className={cn('inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset', style)}><ShieldCheck className="size-3" />{rating.replace('_', ' ')}</span>
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
    <Card title="New Asset">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Key"><Input value={key} onChange={(event) => setKey(event.target.value)} placeholder="mobile-banking" autoFocus /></Field>
          <Field label="Name"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Mobile Banking App" /></Field>
          <Field label="Type"><Select value={type} onValueChange={(value) => setType(value as BusinessAssetType)} options={TYPES.slice(1)} /></Field>
          <Field label="Criticality"><Select value={criticality} onValueChange={(value) => setCriticality(value as BusinessAssetCriticality)} options={CRITICALITIES.slice(1)} /></Field>
          <Field label="Owner"><Input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Mobile Platform Team" /></Field>
          <Field label="Description"><Input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Customer-facing mobile banking product" /></Field>
        </div>
        {error && <ErrorState message={error} />}
        <div className="flex justify-end"><Button variant="brand" type="submit" loading={submitting}>Create Asset</Button></div>
      </form>
    </Card>
  )
}
