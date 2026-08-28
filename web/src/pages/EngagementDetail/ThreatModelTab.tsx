import { AlertTriangle, ArrowRight, Box, Database01, Route, Tag01, User01 } from '@untitledui/icons'
import { useMemo } from 'react'
import { Card, EmptyState, ErrorState, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks'
import { api } from '../../lib/api'
import type { ThreatComponent, ThreatModel } from '../../lib/types'

// kindIcon maps a DFD element kind to a glyph.
function kindIcon(kind: string) {
  switch (kind) {
    case 'external_entity':
      return User01
    case 'data_store':
      return Database01
    default: // process
      return Box
  }
}

function kindLabel(kind: string): string {
  switch (kind) {
    case 'external_entity':
      return 'External entity'
    case 'data_store':
      return 'Data store'
    case 'process':
      return 'Process'
    default:
      return kind || 'component'
  }
}

// classificationTone picks a token color for an asset's data classification.
function classificationTone(c: string): string {
  switch (c.toLowerCase()) {
    case 'secret':
    case 'pii':
      return 'text-critical ring-critical/30 bg-critical/10'
    case 'confidential':
    case 'internal':
      return 'text-high ring-high/30 bg-high/10'
    default:
      return 'text-tertiary ring-secondary bg-secondary'
  }
}

// ThreatModelTab renders the engagement's architecture threat model: its trust boundaries +
// components, its data flows with the boundary CROSSINGS (the attack surface STRIDE reasons over)
// highlighted, and its assets by classification. Read-only; the model is ingested via the API/agent.
export function ThreatModelTab({ engagementId }: { engagementId: string }) {
  const { data: model, loading, error: err } = useFetch<ThreatModel | null>(
    () => api.threatModel(engagementId),
    { deps: [engagementId] },
  )

  const byId = useMemo(() => {
    const m = new Map<string, ThreatComponent>()
    for (const c of model?.components ?? []) m.set(c.id, c)
    return m
  }, [model])

  const boundaryName = useMemo(() => {
    const m = new Map<string, string>()
    for (const b of model?.boundaries ?? []) m.set(b.id, b.name || b.id)
    return m
  }, [model])

  // A flow crosses a trust boundary when its endpoints sit in different boundaries (the domain's
  // BoundaryCrossings rule, recomputed client-side). "" (unzoned) is treated as its own boundary.
  const crosses = (fromID: string, toID: string): boolean => {
    const a = byId.get(fromID)?.boundary ?? ''
    const b = byId.get(toID)?.boundary ?? ''
    return a !== b
  }

  // Flows sorted crossings-first (the attack surface up top), memoized so the copy + sort don't run
  // every render. The local cross() keeps the memo's deps to (model, byId).
  const sortedFlows = useMemo(() => {
    const cross = (fromID: string, toID: string) =>
      (byId.get(fromID)?.boundary ?? '') !== (byId.get(toID)?.boundary ?? '')
    return [...(model?.flows ?? [])].sort((a, b) => Number(cross(b.from, b.to)) - Number(cross(a.from, a.to)))
  }, [model, byId])

  if (err) return <ErrorState message={err} />
  if (loading) return <Spinner label="Loading threat model…" />
  if (model === null) {
    return (
      <EmptyState
        icon={Route}
        title="No threat model ingested"
        hint="Ingest a data-flow diagram (components, flows, trust boundaries, assets) to map the architecture and its attack surface."
      />
    )
  }

  const crossings = model.flows.filter((f) => crosses(f.from, f.to))
  // Boundary groups: each declared boundary plus a synthetic "unzoned" bucket for components with none.
  const groups = [
    ...model.boundaries.map((b) => ({ id: b.id, name: b.name || b.id })),
    { id: '', name: 'Unzoned' },
  ].filter((g) => model.components.some((c) => (c.boundary || '') === g.id))

  const label = (id: string) => byId.get(id)?.name || id

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Components" value={model.components.length} />
        <Stat label="Data flows" value={model.flows.length} />
        <Stat label="Boundary crossings" value={crossings.length} hint="attack surface" emphasis={crossings.length > 0} />
        <Stat label="Assets" value={model.assets.length} />
      </div>

      {/* 2-column balanced grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Left: Trust boundaries & components */}
        <Card title="Trust boundaries & components" className="h-full">
          {groups.length === 0 ? (
            <p className="text-sm text-tertiary">No components.</p>
          ) : (
            <div className="space-y-4">
              {groups.map((g) => (
                <div key={g.id || 'unzoned'}>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-brand-secondary">{g.name}</h3>
                  <ul className="space-y-1.5">
                    {model.components
                      .filter((c) => (c.boundary || '') === g.id)
                      .map((c) => {
                        const Icon = kindIcon(c.kind)
                        return (
                          <li key={c.id} className="flex items-center gap-2.5 rounded-md bg-secondary px-3 py-2">
                            <Icon aria-hidden className="size-4 shrink-0 text-tertiary" />
                            <span className="text-sm font-medium text-primary">{c.name || c.id}</span>
                            <span className="text-xs text-quaternary">{kindLabel(c.kind)}</span>
                            <span className="ml-auto font-mono text-xs text-quaternary">{c.id}</span>
                          </li>
                        )
                      })}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Right: Data flows */}
        <Card
          title="Data flows"
          actions={<span className="text-xs text-tertiary tabular-nums">{model.flows.length} total</span>}
          className="h-full"
        >
          {model.flows.length === 0 ? (
            <p className="text-sm text-tertiary">No data flows.</p>
          ) : (
            <ul className="space-y-1.5">
              {sortedFlows.map((f) => {
                const crossing = crosses(f.from, f.to)
                return (
                  <li
                    key={f.id}
                    className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border border-secondary bg-secondary px-3 py-2"
                  >
                    <span className="text-sm font-medium text-primary">{label(f.from)}</span>
                    <ArrowRight aria-hidden className="size-3.5 text-quaternary" />
                    <span className="text-sm font-medium text-primary">{label(f.to)}</span>
                    {f.data && <span className="text-xs text-tertiary">· {f.data}</span>}
                    {crossing && (
                      <span className="inline-flex items-center gap-1 rounded-md bg-critical/10 px-2 py-0.5 text-xs font-semibold text-critical ring-1 ring-inset ring-critical/30">
                        <AlertTriangle aria-hidden className="size-3" />
                        crosses {boundaryName.get(byId.get(f.from)?.boundary ?? '') ?? 'unzoned'} →{' '}
                        {boundaryName.get(byId.get(f.to)?.boundary ?? '') ?? 'unzoned'}
                      </span>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </Card>
      </div>

      {/* Assets card spanning full width */}
      {model.assets.length > 0 && (
        <Card
          title="Assets"
          actions={<span className="text-xs text-tertiary tabular-nums">{model.assets.length} total</span>}
        >
          <ul className="flex flex-wrap gap-2.5">
            {model.assets.map((a) => (
              <li
                key={a.id}
                className="inline-flex items-center gap-2 rounded-lg border border-secondary bg-secondary px-3 py-2 text-sm text-primary"
              >
                <Tag01 aria-hidden className="size-3.5 text-quaternary" />
                <span className="font-medium">{a.name || a.id}</span>
                {a.classification && (
                  <span
                    className={`rounded px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ring-inset ${classificationTone(a.classification)}`}
                  >
                    {a.classification}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}

function Stat({ label, value, hint, emphasis }: { label: string; value: number; hint?: string; emphasis?: boolean }) {
  return (
    <div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
      <div className={`font-mono text-2xl font-semibold tabular-nums ${emphasis ? 'text-critical' : 'text-primary'}`}>
        {value}
      </div>
      <div className="text-xs text-tertiary">{label}</div>
      {hint && <div className="text-xs text-quaternary">{hint}</div>}
    </div>
  )
}
