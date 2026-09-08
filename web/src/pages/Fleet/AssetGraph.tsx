import { useMemo, useState } from 'react'
import { ArrowRight, Dataflow03, SearchLg } from '@untitledui/icons'
import { api } from '../../lib/api'
import type { AssetEdge, AssetEdgeConfidence, AssetEdgeKind } from '../../lib/api'
import type { TechnicalAsset } from '../../lib/types'
import { Button, Card, EmptyState, ErrorState, InfoNote, Input, Pill, Select, Spinner, cn } from '../../components/ui'
import { FeatureDisabledState, isFeatureDisabled } from '../../components/synapse/FeatureDisabledState'
import { useFetch } from '../../hooks'

const EDGE_KINDS: AssetEdgeKind[] = ['runs', 'exposes', 'depends_on', 'can_assume', 'reaches', 'affected_by', 'mounts']
const KIND_LABEL: Record<string, string> = {
  runs: 'runs', exposes: 'exposes', depends_on: 'depends on', can_assume: 'can assume', reaches: 'reaches', affected_by: 'affected by', mounts: 'mounts',
}

function assetKindTone(kind: string): string {
  switch (kind) {
    case 'host': return 'text-brand-secondary'
    case 'workload': return 'text-success-primary'
    case 'image': return 'text-warning-primary'
    case 'exposure': return 'text-error-primary'
    case 'identity': case 'cloud_account': return 'text-utility-purple-600'
    default: return 'text-tertiary'
  }
}

function AssetChip({ id, byId }: { id: string; byId: Map<string, TechnicalAsset> }) {
  const a = byId.get(id)
  const label = a?.name || a?.key || id
  const kind = a?.kind || 'asset'
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5" title={id}>
      <span className={cn('rounded border border-current/25 px-1 py-0.5 text-[10px] font-bold uppercase', assetKindTone(kind))}>{kind}</span>
      <span className="truncate text-sm font-medium text-primary">{label}</span>
    </span>
  )
}

function EdgeRow({ edge, byId }: { edge: AssetEdge; byId: Map<string, TechnicalAsset> }) {
  const inferred = edge.confidence === 'inferred'
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border border-secondary bg-primary px-4 py-3">
      <AssetChip id={edge.from} byId={byId} />
      <span className="inline-flex items-center gap-1.5 text-xs text-tertiary">
        <span className={cn('inline-block w-8 border-t', inferred ? 'border-dashed border-quaternary' : 'border-solid border-brand-solid')} aria-hidden />
        <span className="font-mono">{KIND_LABEL[edge.kind] ?? edge.kind}</span>
        <ArrowRight className="size-3.5" aria-hidden />
      </span>
      <AssetChip id={edge.to} byId={byId} />
      <div className="ml-auto flex items-center gap-2">
        {inferred ? (
          <InfoNote label="Inferred">
            This relationship was inferred, not directly observed. It is drawn dashed. Treat it as a lead to
            confirm rather than a confirmed edge.
          </InfoNote>
        ) : (
          <Pill className="bg-success-primary/10 text-success-primary ring-1 ring-inset ring-success-primary/25">observed</Pill>
        )}
        {edge.provenance && <span className="font-mono text-[11px] text-quaternary" title={`provenance ${edge.provenance}`}>{edge.provenance}</span>}
      </div>
    </div>
  )
}

function CreateEdgeForm({ assets, onCreated }: { assets: TechnicalAsset[]; onCreated: () => void }) {
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [kind, setKind] = useState<AssetEdgeKind>('depends_on')
  const [confidence, setConfidence] = useState<AssetEdgeConfidence>('observed')
  const [provenance, setProvenance] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const options = assets.map((a) => ({ value: a.id, label: `${a.name || a.key || a.id} (${a.kind})` }))
  const ready = from && to && from !== to && provenance.trim()

  async function submit() {
    if (!ready) return
    setBusy(true)
    setErr('')
    try {
      await api.createAssetEdge({ from, to, kind, provenance: provenance.trim(), confidence })
      setProvenance('')
      onCreated()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not create the relationship')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3 rounded-lg border border-secondary bg-secondary/30 p-3">
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold text-primary">Add a relationship</span>
        <InfoNote label="Provenance is required">
          Every edge carries the observation id it came from. An edge is idempotent by (from, to, kind,
          provenance), so re-adding the same observation does not duplicate it.
        </InfoNote>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">From</span>
          <Select ariaLabel="Edge from asset" value={from} onValueChange={setFrom} options={options} placeholder="source asset" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Kind</span>
          <Select ariaLabel="Edge kind" value={kind} onValueChange={(v) => setKind(v as AssetEdgeKind)} options={EDGE_KINDS.map((k) => ({ value: k, label: KIND_LABEL[k] }))} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">To</span>
          <Select ariaLabel="Edge to asset" value={to} onValueChange={setTo} options={options} placeholder="target asset" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Confidence</span>
          <Select ariaLabel="Edge confidence" value={confidence} onValueChange={(v) => setConfidence(v as AssetEdgeConfidence)} options={[{ value: 'observed', label: 'observed' }, { value: 'inferred', label: 'inferred' }]} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-tertiary">Provenance</span>
          <Input value={provenance} onChange={(e) => setProvenance(e.target.value)} placeholder="observation id" className="font-mono" aria-label="Edge provenance" />
        </label>
      </div>
      <div className="flex items-center gap-3">
        <Button variant="primary" loading={busy} disabled={busy || !ready} onClick={submit}>Add relationship</Button>
        {from && to && from === to && <span className="text-xs text-warning-primary">Pick two different assets.</span>}
        {err && <span className="text-sm text-error-primary">{err}</span>}
      </div>
    </div>
  )
}

export function AssetGraph() {
  const { data: assets, loading: la, error: ea, refetch: refetchAssets } = useFetch<TechnicalAsset[]>(() => api.listTechnicalAssets(), { deps: [] })
  const { data: edges, loading: le, error: ee, refetch: refetchEdges } = useFetch<AssetEdge[]>(() => api.fleetAssetEdges(), { deps: [] })
  const { data: me } = useFetch(() => api.me(), { deps: [] })
  const canOperate = me?.role === 'admin' || me?.role === 'consultant' || me?.role === 'member'
  const [filter, setFilter] = useState('')

  const byId = useMemo(() => new Map((assets ?? []).map((a) => [a.id, a])), [assets])
  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return edges ?? []
    return (edges ?? []).filter((e) => {
      const f = byId.get(e.from)
      const t = byId.get(e.to)
      return `${e.from} ${e.to} ${e.kind} ${f?.name ?? ''} ${f?.key ?? ''} ${t?.name ?? ''} ${t?.key ?? ''}`.toLowerCase().includes(q)
    })
  }, [edges, filter, byId])

  const error = ea || ee
  if (error && isFeatureDisabled(error)) {
    return (
      <div className="mx-auto max-w-[1200px] p-4">
        <FeatureDisabledState feature="Asset relationship graph" envVar="SYNAPSE_FLEET_ASSETS_ENABLED" hint="The technical asset graph needs the fleet asset model." />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1200px] animate-fade-in space-y-5 p-4 pb-12">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-primary">
          <Dataflow03 className="size-6 text-tertiary" aria-hidden /> Asset graph
        </h1>
        <p className="text-sm text-tertiary">How technical assets relate: which host runs which workload, what an image depends on, what an exposure reaches.</p>
      </header>

      <Card
        title="Relationships"
        titleClassName="flex items-center gap-2"
        actions={
          <div className="flex items-center gap-2">
            <InfoNote label="Observed vs inferred">
              A solid edge was directly observed; a dashed edge was inferred and is a lead to confirm. Each
              edge names the observation it came from.
            </InfoNote>
            <div className="relative">
              <SearchLg className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-quaternary" />
              <Input aria-label="Filter relationships" placeholder="Filter by asset or kind" value={filter} onChange={(e) => setFilter(e.target.value)} className="w-60 pl-8" />
            </div>
          </div>
        }
      >
        <div className="space-y-4">
          {canOperate && assets && assets.length > 0 && <CreateEdgeForm assets={assets} onCreated={() => { refetchEdges(); refetchAssets() }} />}

          {error ? (
            <ErrorState message={error} />
          ) : (le || la) && !edges ? (
            <div className="flex justify-center py-6"><Spinner /></div>
          ) : (edges?.length ?? 0) === 0 ? (
            <EmptyState icon={Dataflow03} title="No relationships yet" hint="Asset relationships are produced by the scanners and fleet agents, or added here from an observation." />
          ) : visible.length === 0 ? (
            <EmptyState icon={SearchLg} title="No relationships match" hint="No edge matches the current filter." />
          ) : (
            <div className="space-y-2">
              <div className="text-xs text-quaternary">{visible.length === (edges?.length ?? 0) ? `${edges?.length ?? 0} relationships` : `${visible.length} of ${edges?.length ?? 0} relationships`}</div>
              {visible.map((e, i) => <EdgeRow key={`${e.from}-${e.to}-${e.kind}-${e.provenance}-${i}`} edge={e} byId={byId} />)}
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}

export default AssetGraph
