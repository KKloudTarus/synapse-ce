import { ApiError, req } from './client'

/**
 * Attack paths (tenant-wide) join estate assets to findings through evidence-carrying edges. The graph
 * traversal is bounded server-side (max length, max paths, wall clock); `bounds.truncated` says the
 * returned set is partial. A path is `confident` only when every edge is observed and the terminal
 * finding is confirmed-reachable; otherwise `uncertainties` names why. The route registers only when the
 * attack-path service is wired, so the client treats a 404 as "not enabled in this deployment".
 *
 * SOURCE OF TRUTH: `internal/domain/attackpath/{graph,score,traverse}.go` and the handler in
 * `internal/adapter/httpapi/attackpath_handler.go`. Note the nested `asset.Asset` and `finding.Finding`
 * carry no JSON tags, so they arrive PascalCase; the mappers below read both cases defensively.
 */

export type AttackPathNodeKind = 'asset' | 'finding'

export interface AttackPathNode {
  id: string
  kind: AttackPathNodeKind
  label: string
  sublabel: string
  severity?: string
  reachability?: string
  confirmed?: boolean
  external?: boolean
}

export interface AttackPathStep {
  from: string
  to: string
  kind: string
  observed: boolean
  toFinding: boolean
  evidenceCount: number
}

export interface AttackPath {
  id: string
  confident: boolean
  uncertainties: string[]
  nodes: AttackPathNode[]
  steps: AttackPathStep[]
}

export interface AttackPathBounds {
  truncated: boolean
  lengthHit: boolean
  pathsHit: boolean
  wallClockHit: boolean
  maxLength: number
  maxPaths: number
}

export interface AttackPathResult {
  paths: AttackPath[]
  bounds: AttackPathBounds
}

export interface AttackPathQuery {
  target?: string
  entrypoint?: string
  finding?: string
  findingKind?: 'canonical' | 'imported'
}

function assetLabel(a: any): { id: string; label: string; sublabel: string } {
  const id = a?.ID ?? a?.id ?? ''
  const name = a?.Name ?? a?.name ?? ''
  const key = a?.Key ?? a?.key ?? ''
  const kind = a?.Kind ?? a?.kind ?? 'asset'
  return { id, label: name || key || id, sublabel: String(kind) }
}

function mapNode(n: any): AttackPathNode | null {
  if (n?.asset) {
    const { id, label, sublabel } = assetLabel(n.asset.asset ?? n.asset.Asset)
    return { id, kind: 'asset', label, sublabel }
  }
  if (n?.finding) {
    const input = n.finding.input ?? n.finding.Input ?? {}
    const f = input.finding ?? input.Finding ?? {}
    const target = input.target ?? input.Target ?? {}
    const id = target.ID ?? target.id ?? f.ID ?? f.id ?? ''
    const title = f.Title ?? f.title ?? id
    const severity = String(f.Severity ?? f.severity ?? '').toLowerCase() || undefined
    return {
      id,
      kind: 'finding',
      label: title,
      sublabel: severity ? `${severity} finding` : 'finding',
      severity,
      reachability: input.reachability ?? input.Reachability ?? undefined,
      confirmed: input.confirmed ?? input.Confirmed ?? undefined,
      external: input.external ?? input.External ?? undefined,
    }
  }
  return null
}

function mapStep(s: any): AttackPathStep {
  return {
    from: s?.from ?? '',
    to: s?.to ?? '',
    kind: s?.kind ?? '',
    observed: s?.observed === true,
    toFinding: s?.toFinding === true,
    evidenceCount: Array.isArray(s?.evidence) ? s.evidence.length : 0,
  }
}

function mapPath(p: any): AttackPath {
  return {
    id: p?.id ?? '',
    confident: p?.confident === true,
    uncertainties: Array.isArray(p?.uncertainties) ? p.uncertainties.map(String) : [],
    nodes: Array.isArray(p?.nodes) ? p.nodes.map(mapNode).filter((n: AttackPathNode | null): n is AttackPathNode => n !== null) : [],
    steps: Array.isArray(p?.steps) ? p.steps.map(mapStep) : [],
  }
}

function mapBounds(b: any): AttackPathBounds {
  return {
    truncated: b?.truncated === true,
    lengthHit: b?.lengthHit === true,
    pathsHit: b?.pathsHit === true,
    wallClockHit: b?.wallClockHit === true,
    maxLength: b?.maxLength ?? 0,
    maxPaths: b?.maxPaths ?? 0,
  }
}

export const attackPathsApi = {
  /** null when the deployment does not expose attack paths (route 404). */
  attackPaths: async (query: AttackPathQuery = {}): Promise<AttackPathResult | null> => {
    const p = new URLSearchParams()
    if (query.target) p.set('target', query.target)
    if (query.entrypoint) p.set('entrypoint', query.entrypoint)
    if (query.finding) p.set('finding', query.finding)
    if (query.findingKind) p.set('finding_kind', query.findingKind)
    const qs = p.toString()
    try {
      const r = await req(`/attack-paths${qs ? `?${qs}` : ''}`)
      return {
        paths: Array.isArray(r?.paths) ? r.paths.map(mapPath) : [],
        bounds: mapBounds(r?.bounds),
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },
}
