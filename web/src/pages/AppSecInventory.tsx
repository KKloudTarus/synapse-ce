import { useEffect, useState } from 'react'
import { Boxes, Building2, RefreshCw, ShieldCheck } from 'lucide-react'
import { Card, EmptyState, ErrorState, Spinner } from '../components/ui'
import { api } from '../lib/api'
import type { AppSecAsset, AppSecBusinessService } from '../lib/types'

export function AppSecInventory() {
  const [services, setServices] = useState<AppSecBusinessService[] | null>(null)
  const [assets, setAssets] = useState<AppSecAsset[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const load = () => {
    setError(null)
    Promise.all([api.listAppSecBusinessServices(), api.listAppSecAssets()])
      .then(([nextServices, nextAssets]) => { setServices(nextServices); setAssets(nextAssets) })
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'Failed to load Asset Inventory'))
  }
  useEffect(load, [])
  if (error) return <main className="p-6"><ErrorState message={error} onRetry={load} /></main>
  if (!services || !assets) return <main className="flex min-h-64 items-center justify-center"><Spinner /> <span className="ml-2 text-mutedfg">Loading Asset Inventory…</span></main>
  return <main className="mx-auto w-full max-w-7xl p-5 md:p-8">
    <header className="mb-7 flex flex-wrap items-start justify-between gap-4">
      <div><div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-branddim"><ShieldCheck className="size-4" /> AppSec foundation</div><h1 className="text-3xl font-bold tracking-tight">Asset Inventory</h1><p className="mt-1.5 max-w-2xl text-sm text-mutedfg">Business Services own long-lived security posture. Assets are reusable technical records for future Assessments and scheduled scans.</p></div>
      <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm font-medium hover:bg-raised"><RefreshCw className="size-4" /> Refresh</button>
    </header>
    <section className="grid gap-4 md:grid-cols-2">
      <Card className="p-5"><div className="mb-4 flex items-center gap-2"><Building2 className="size-5 text-brand" /><h2 className="font-semibold">Business Services</h2><span className="ml-auto rounded-full bg-brand/10 px-2 py-0.5 text-xs text-branddim">{services.length}</span></div>{services.length === 0 ? <EmptyState title="No Business Services yet" hint="Create the first service to establish its AppSec management boundary." /> : <div className="space-y-3">{services.map((service) => <div key={service.id} className="rounded-lg border border-border bg-elevated p-3"><div className="font-medium">{service.name}</div><div className="mt-1 flex gap-2 text-xs text-mutedfg"><span>{service.code}</span>{service.owner && <span>· {service.owner}</span>}{service.criticality && <span>· {service.criticality}</span>}</div></div>)}</div>}</Card>
      <Card className="p-5"><div className="mb-4 flex items-center gap-2"><Boxes className="size-5 text-brand" /><h2 className="font-semibold">Technical Assets</h2><span className="ml-auto rounded-full bg-brand/10 px-2 py-0.5 text-xs text-branddim">{assets.length}</span></div>{assets.length === 0 ? <EmptyState title="No Assets yet" hint="Register web, mobile, cloud, API, repository, image, or SBOM assets." /> : <div className="space-y-3">{assets.map((asset) => <div key={asset.id} className="rounded-lg border border-border bg-elevated p-3"><div className="flex items-center justify-between gap-3"><div className="font-medium">{asset.name}</div><span className="rounded bg-surface px-2 py-0.5 font-mono text-xs text-branddim">{asset.category}</span></div><div className="mt-1 truncate font-mono text-xs text-mutedfg">{asset.identity.value}</div><div className="mt-2 text-xs text-mutedfg">{asset.lifecycle}{asset.owner ? ` · ${asset.owner}` : ''}{asset.exposure ? ` · ${asset.exposure}` : ''}</div></div>)}</div>}</Card>
    </section>
  </main>
}
