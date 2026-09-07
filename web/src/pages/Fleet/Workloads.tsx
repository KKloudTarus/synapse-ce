import { useMemo, useState } from 'react'
import { Cube01, Dataflow03, SearchLg, Server01 } from '@untitledui/icons'
import { Card, EmptyState, ErrorState, InfoNote, Pill, Spinner, cn } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { Workload } from '../../lib/api'

function shortDigest(d: string): string {
  const bare = d.replace(/^sha256:/, '')
  return bare.length > 12 ? `sha256:${bare.slice(0, 12)}…` : d
}

function kindTone(kind: string): string {
  switch (kind) {
    case 'Deployment':
      return 'text-brand-secondary'
    case 'StatefulSet':
      return 'text-warning-primary'
    case 'DaemonSet':
      return 'text-success-primary'
    default:
      return 'text-tertiary'
  }
}

function WorkloadRow({ wl, sharedBy }: { wl: Workload; sharedBy: (digest: string) => number }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2 rounded-lg border border-secondary bg-primary px-4 py-3">
      <div className="flex items-center gap-2">
        <Server01 className="size-4 shrink-0 text-tertiary" aria-hidden />
        <span className={cn('rounded border border-current/25 px-1.5 py-0.5 text-[11px] font-bold', kindTone(wl.kind))}>{wl.kind || 'Workload'}</span>
        <span className="text-sm font-semibold text-primary">{wl.name}</span>
        {wl.serviceAccount && wl.serviceAccount !== 'default' && (
          <span className="text-xs text-quaternary">sa: {wl.serviceAccount}</span>
        )}
      </div>
      <ul className="flex flex-col gap-1">
        {wl.images.length === 0 ? (
          <li className="text-xs text-quaternary">no resolved image digest</li>
        ) : (
          wl.images.map((img) => {
            const others = sharedBy(img.digest) - 1
            return (
              <li key={img.digest} className="flex flex-wrap items-center gap-2 text-xs">
                <Cube01 className="size-3.5 shrink-0 text-quaternary" aria-hidden />
                <span className="text-secondary" title={img.ref}>{img.ref || '(unknown ref)'}</span>
                <span className="font-mono text-quaternary" title={img.digest}>{shortDigest(img.digest)}</span>
                {others > 0 && (
                  <Pill className="text-warning-primary">
                    also runs in {others} other workload{others === 1 ? '' : 's'}
                  </Pill>
                )}
              </li>
            )
          })
        )}
      </ul>
    </div>
  )
}

export function Workloads() {
  const { data, loading, error } = useFetch<Workload[]>(() => api.fleetWorkloads(), { deps: [] })
  const [filter, setFilter] = useState('')

  const workloads = useMemo(() => data ?? [], [data])
  // digest -> count of workloads running it, so a CVE on an image can be traced to every workload.
  const digestCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const wl of workloads) for (const img of wl.images) m.set(img.digest, (m.get(img.digest) ?? 0) + 1)
    return m
  }, [workloads])
  const sharedBy = (digest: string) => digestCounts.get(digest) ?? 0

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return workloads
    return workloads.filter(
      (w) => w.name.toLowerCase().includes(q) || w.namespace.toLowerCase().includes(q) || w.kind.toLowerCase().includes(q) || w.images.some((i) => i.ref.toLowerCase().includes(q) || i.digest.includes(q)),
    )
  }, [workloads, filter])

  const byNamespace = useMemo(() => {
    const groups = new Map<string, Workload[]>()
    for (const w of visible) {
      const key = `${w.cluster}/${w.namespace}`
      const arr = groups.get(key) ?? []
      arr.push(w)
      groups.set(key, arr)
    }
    return [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
  }, [visible])

  if (loading) return <Spinner label="Loading workloads…" />
  if (error) return <ErrorState message={error} />

  return (
    <div className="mx-auto max-w-[1600px] animate-fade-in space-y-6 pb-12">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-primary sm:text-display-xs">Kubernetes Workloads</h1>
          <InfoNote label="About workloads">
            The workload-to-image map from an enrolled cluster agent. A container CVE found on an image digest traces to
            every workload that runs it, so you can tell which deployment or statefulset it came from.
          </InfoNote>
        </div>
        {workloads.length > 0 && (
          <span className="text-sm text-tertiary">
            {workloads.length} workload{workloads.length === 1 ? '' : 's'}
          </span>
        )}
      </header>

      {workloads.length === 0 ? (
        <EmptyState
          icon={Dataflow03}
          title="No cluster inventory yet"
          hint="Enrol a synapse-cluster-agent against a Kubernetes cluster. It maps every workload to the image digests it runs, so a CVE on an image can be attributed to its deployment, statefulset, or daemonset."
        />
      ) : (
        <>
          <div className="relative max-w-md">
            <SearchLg className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-quaternary" aria-hidden />
            <input
              type="search"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by workload, namespace, or image…"
              aria-label="Filter workloads"
              className="input-inset w-full rounded-lg border border-secondary bg-secondary py-2 pl-9 pr-3 text-sm text-primary outline-none transition-colors placeholder:text-quaternary focus:border-brand focus:ring-2 focus:ring-brand/40"
            />
          </div>

          {byNamespace.length === 0 ? (
            <EmptyState icon={SearchLg} title="No workloads match" hint="Clear the filter." />
          ) : (
            byNamespace.map(([nsKey, group]) => (
              <Card key={nsKey} title={nsKey} titleClassName="font-mono">
                <div className="space-y-2">
                  {group.map((wl) => (
                    <WorkloadRow key={`${wl.kind}/${wl.name}`} wl={wl} sharedBy={sharedBy} />
                  ))}
                </div>
              </Card>
            ))
          )}
        </>
      )}
    </div>
  )
}

export default Workloads
