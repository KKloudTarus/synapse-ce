import { Activity, Boxes, Briefcase, CheckCircle2, Plus, Target, Trash2, Upload } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { Button, Card, cn, EmptyState, ErrorState, Field, Input, Pill, Select, Spinner } from '../components/ui'
import { kindLabel } from '../lib/format'
import { api } from '../lib/api'
import { useFetch } from '../hooks'
import type { BusinessAsset, Engagement, ScopeTarget } from '../lib/types'

const KINDS = ['repo', 'domain', 'host', 'url', 'image', 'cidr']

export function Engagements() {
  const [searchParams] = useSearchParams()
  const [importing, setImporting] = useState(false)
  const [importErr, setImportErr] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  const { data, error } = useFetch<{ list: Engagement[]; assetNames: Record<string, string> }>(
    async () => {
      const engagements = await api.listEngagements()
      let assetNames: Record<string, string> = {}
      try {
        const page = await api.listBusinessAssets('limit=200')
        assetNames = Object.fromEntries(page.items.map((asset) => [asset.id, asset.name]))
      } catch { /* ignore asset name failures */ }
      return { list: engagements, assetNames }
    },
    { deps: [] },
  )

  const list = data?.list ?? null
  const assetNames = data?.assetNames ?? {}

  async function onImportFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setImporting(true)
    setImportErr(null)
    try {
      const engagement = await api.importBundle(await file.text())
      navigate(`/engagements/${engagement.id}`)
    } catch (nextError) {
      setImportErr(nextError instanceof Error ? nextError.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  const engagements = list ?? []
  const activeCount = engagements.filter((engagement) => engagement.status.toLowerCase() === 'active').length
  const completedCount = engagements.filter((engagement) => engagement.status.toLowerCase() === 'completed').length
  const unassignedCount = engagements.filter((engagement) => !engagement.businessAssetId).length

  if (searchParams.get('create') === '1') {
    const assetId = searchParams.get('assetId')
    return <Navigate replace to={assetId ? `/engagements/new?${new URLSearchParams({ assetId }).toString()}` : '/engagements/new'} />
  }

  return (
    <div className="mx-auto max-w-[1480px] animate-fade-in">
      <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-branddim">Assessment operations</p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Engagements</h1>
          <p className="mt-2 max-w-3xl text-sm text-mutedfg sm:text-base">
            Define authorized assessment scopes, connect them to business Assets, and follow execution through completion.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={onImportFile} />
          <Button variant="secondary" loading={importing} onClick={() => fileRef.current?.click()}>
            <Upload className="size-4" />Import bundle
          </Button>
          <Link to="/engagements/new" className="btn-primary inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold text-brandfg transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg">
            <Plus className="size-4" />New Engagement
          </Link>
        </div>
      </header>

      {importErr && <div className="mb-6"><ErrorState message={importErr} /></div>}

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <EngagementStat icon={Target} label="Total" value={list ? engagements.length : '—'} />
        <EngagementStat icon={Activity} label="Active" value={list ? activeCount : '—'} tone="accent" />
        <EngagementStat icon={CheckCircle2} label="Completed" value={list ? completedCount : '—'} tone="brand" />
        <EngagementStat icon={Boxes} label="Unassigned" value={list ? unassignedCount : '—'} tone={unassignedCount ? 'high' : 'muted'} />
      </div>

      {error && <ErrorState message={error} />}
      {!list && !error && <Spinner label="Loading engagements…" />}
      {list && list.length === 0 && (
        <EmptyState
          icon={Target}
          title="No engagements yet"
          hint="Create one to define an authorized testing scope and connect the assessment to an Asset."
          action={<Link to="/engagements/new" className="btn-primary inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold text-brandfg transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg"><Plus className="size-4" />New Engagement</Link>}
        />
      )}
      {list && list.length > 0 && (
        <Card title="Assessment queue" actions={<span className="text-sm text-mutedfg">{list.length} Engagement{list.length === 1 ? '' : 's'}</span>} bodyClass="divide-y divide-border p-0">
          {list.map((engagement) => (
            <EngagementRow key={engagement.id} engagement={engagement} assetName={engagement.businessAssetId ? assetNames[engagement.businessAssetId] : undefined} />
          ))}
        </Card>
      )}
    </div>
  )
}

export function NewEngagement() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const initialAssetId = searchParams.get('assetId') ?? ''

  return (
    <div className="mx-auto max-w-[1480px] animate-fade-in">
      <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-branddim">Assessment operations</p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">New Engagement</h1>
          <p className="mt-2 max-w-3xl text-sm text-mutedfg sm:text-base">Define an authorized assessment scope and connect it to a business Asset.</p>
        </div>
        <Link to="/engagements" className="inline-flex items-center justify-center rounded-lg border border-border bg-elevated px-3.5 py-2 text-sm font-semibold text-foreground transition hover:border-borderstrong hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg">Cancel</Link>
      </header>

      <CreateForm initialAssetId={initialAssetId} onCreated={() => navigate('/engagements')} />
    </div>
  )
}

function EngagementStat({ icon: Icon, label, value, tone = 'muted' }: { icon: typeof Target; label: string; value: number | string; tone?: 'muted' | 'accent' | 'brand' | 'high' }) {
  const iconTone = {
    muted: 'bg-muted text-mutedfg',
    accent: 'bg-accent/10 text-accent',
    brand: 'bg-brand/10 text-branddim',
    high: 'bg-high/10 text-high',
  }[tone]
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <div><div className="text-2xl font-bold tabular-nums sm:text-3xl">{value}</div><div className="mt-1 text-xs font-medium text-mutedfg sm:text-sm">{label}</div></div>
        <span className={cn('flex size-9 items-center justify-center rounded-lg', iconTone)}><Icon className="size-4" /></span>
      </div>
    </div>
  )
}

function EngagementRow({ engagement, assetName }: { engagement: Engagement; assetName?: string }) {
  return (
    <Link to={`/engagements/${engagement.id}`} className="group grid gap-3 p-4 transition-colors hover:bg-elevated sm:grid-cols-[minmax(0,1.4fr)_minmax(160px,0.8fr)_auto] sm:items-center sm:px-5">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="truncate font-semibold group-hover:text-branddim">{engagement.name || 'Untitled'}</h2>
          <StatusPill status={engagement.status} />
        </div>
        <p className="mt-1 truncate font-mono text-xs text-subtlefg">{engagement.id}</p>
      </div>
      <div className="min-w-0 text-sm text-mutedfg">
        {engagement.client && <div className="flex items-center gap-1.5 truncate"><Briefcase className="size-3.5" />{engagement.client}</div>}
        <div className="mt-1 flex items-center gap-1.5 truncate"><Boxes className="size-3.5" />{engagement.businessAssetId ? assetName || engagement.businessAssetId : 'Unassigned'}</div>
      </div>
      <div className="flex flex-wrap items-center gap-2 sm:justify-end">
        <Pill><Target className="size-3" />{engagement.inScope.length} in scope</Pill>
        {engagement.outOfScope.length > 0 && <Pill>{engagement.outOfScope.length} excluded</Pill>}
      </div>
    </Link>
  )
}

export function StatusPill({ status }: { status: string }) {
  const value = (status || 'draft').toLowerCase()
  const tone = value === 'active'
    ? 'bg-accent/10 text-accent ring-accent/25'
    : value === 'completed'
      ? 'bg-brand/10 text-branddim ring-brand/25'
      : value === 'archived'
        ? 'bg-muted text-mutedfg ring-border'
        : 'bg-info/10 text-info ring-info/25'
  return <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset', tone)}>{value}</span>
}

function CreateForm({ initialAssetId, onCreated }: { initialAssetId?: string; onCreated: () => void }) {
  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const [scope, setScope] = useState<ScopeTarget[]>([{ kind: 'repo', value: '' }])
  const [authFrom, setAuthFrom] = useState('')
  const [authTo, setAuthTo] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [assets, setAssets] = useState<BusinessAsset[]>([])
  const [assetId, setAssetId] = useState(initialAssetId ?? '')

  useEffect(() => {
    let live = true
    api.listBusinessAssets('limit=200')
      .then((result) => {
        if (!live) return
        const assignable = result.items.filter((asset) => asset.lifecycle !== 'retired')
        setAssets(assignable)
        if (initialAssetId && !assignable.some((asset) => asset.id === initialAssetId)) setAssetId('')
      })
      .catch(() => {
        if (!live) return
        setAssets([])
        setAssetId('')
      })
    return () => {
      live = false
    }
  }, [initialAssetId])

  function setRow(index: number, patch: Partial<ScopeTarget>) {
    setScope((rows) => rows.map((row, rowIndex) => rowIndex === index ? { ...row, ...patch } : row))
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    const inScope = scope.filter((row) => row.value.trim() !== '')
    if (!name.trim()) {
      setError('Name is required.')
      return
    }
    if (inScope.length === 0) {
      setError('Add at least one in-scope target.')
      return
    }
    if (assetId && !assets.some((asset) => asset.id === assetId)) {
      setError('Select a valid Asset.')
      return
    }
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone
    const from = authFrom ? new Date(authFrom).toISOString() : undefined
    const to = authTo ? new Date(authTo).toISOString() : undefined
    if (from && to && new Date(from) >= new Date(to)) {
      setError('Authorization start must be before end.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      await api.createEngagement({
        name: name.trim(),
        client: client.trim(),
        inScope,
        outOfScope: [],
        authorizedFrom: from,
        authorizedTo: to,
        timezone: from || to ? timezone : undefined,
        assetId,
      })
      onCreated()
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Failed to create engagement')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card title="Engagement details" className="border-brand/25">
      <form onSubmit={submit} className="space-y-5">
        <div>
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold"><span className="flex size-6 items-center justify-center rounded-full bg-brand text-xs text-brandfg">1</span>Assessment context</div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <Field label="Name"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="acme-q3-2026" autoFocus /></Field>
            <Field label="Client" hint="Optional"><Input value={client} onChange={(event) => setClient(event.target.value)} placeholder="Acme Corp" /></Field>
            <Field label="Asset" hint="Optional; unassigned remains supported"><Select value={assetId} onValueChange={setAssetId} options={[{ value: '', label: 'Unassigned' }, ...assets.map((asset) => ({ value: asset.id, label: `${asset.name} (${asset.key})` }))]} className="w-full" /></Field>
          </div>
        </div>

        <div className="border-t border-border pt-5">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold"><span className="flex size-6 items-center justify-center rounded-full bg-brand text-xs text-brandfg">2</span>In-scope targets</div>
          <div className="space-y-2">
            {scope.map((row, index) => (
              <div key={index} className="flex gap-2">
                <Select value={row.kind} onValueChange={(value) => setRow(index, { kind: value })} ariaLabel="Target kind" options={KINDS.map((kind) => ({ value: kind, label: kindLabel(kind) }))} />
                <Input value={row.value} onChange={(event) => setRow(index, { value: event.target.value })} placeholder="/path/to/repo or app.acme.io" className="font-mono" />
                {scope.length > 1 && <button type="button" onClick={() => setScope((rows) => rows.filter((_, rowIndex) => rowIndex !== index))} className="rounded-lg px-2 text-mutedfg transition-colors hover:bg-elevated hover:text-high" aria-label="Remove target"><Trash2 className="size-4" /></button>}
              </div>
            ))}
            <button type="button" onClick={() => setScope((rows) => [...rows, { kind: 'repo', value: '' }])} className="inline-flex items-center gap-1 text-xs font-medium text-branddim hover:underline"><Plus className="size-3" />Add target</button>
          </div>
        </div>

        <div className="border-t border-border pt-5">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold"><span className="flex size-6 items-center justify-center rounded-full bg-brand text-xs text-brandfg">3</span>Authorization window</div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Authorized from" hint="Optional – testing is refused before this" htmlFor="auth-from"><Input id="auth-from" type="datetime-local" value={authFrom} onChange={(event) => setAuthFrom(event.target.value)} /></Field>
            <Field label="Authorized to" hint="Optional – testing is refused after this" htmlFor="auth-to"><Input id="auth-to" type="datetime-local" value={authTo} onChange={(event) => setAuthTo(event.target.value)} /></Field>
          </div>
        </div>

        {error && <ErrorState message={error} />}
        <div className="flex justify-end"><Button variant="brand" type="submit" loading={submitting}>Create Engagement</Button></div>
      </form>
    </Card>
  )
}
