import { req } from './client'

// Attack paths (#... attackpath): root-to-finding traversals over the asset/finding graph. Each path is
// an ordered chain of nodes (assets and a terminal finding) connected by evidence-carrying steps. A path
// is "confident" only when every step is observed; otherwise it carries uncertainties (an inferred edge,
// missing/unknown/unconfirmed reachability). The traversal is bounded, so a result can be truncated.
//
// The wire nests a PascalCase asset.Asset inside a camelCase-tagged node, so the mapper tolerates both.

export interface AttackPathNode {
  id: string
  label: string
  kind: 'asset' | 'finding'
  detail: string
}

export interface AttackPathStep {
  kind: string
  observed: boolean
  toFinding: boolean
}

export interface AttackPath {
  id: string
  nodes: AttackPathNode[]
  steps: AttackPathStep[]
  uncertainties: string[]
  confident: boolean
}

export interface AttackPathResult {
  paths: AttackPath[]
  truncated: boolean
}

export interface AttackPathFilters {
  target?: string
  entrypoint?: string
  finding?: string
}

function findingLabel(input: any): { label: string; detail: string } {
  const f = input?.finding ?? {}
  const label = f.Title ?? f.title ?? f.RuleID ?? f.rule_id ?? input?.target?.id ?? input?.target?.ID ?? 'finding'
  const sev = f.Severity ?? f.severity ?? ''
  const reach = input?.reachability ?? ''
  const detail = [sev, reach && `reachability ${reach}`].filter(Boolean).join(' · ')
  return { label: String(label), detail }
}

function mapNode(n: any): AttackPathNode {
  if (n?.asset) {
    const a = n.asset.asset ?? n.asset.Asset ?? {}
    return {
      id: a.ID ?? a.id ?? '',
      label: a.Name ?? a.name ?? a.Key ?? a.key ?? 'asset',
      kind: 'asset',
      detail: String(a.Kind ?? a.kind ?? ''),
    }
  }
  const input = n?.finding?.input ?? n?.finding?.Input ?? {}
  const { label, detail } = findingLabel(input)
  return { id: input?.target?.id ?? input?.target?.ID ?? '', label, kind: 'finding', detail }
}

function mapPath(p: any): AttackPath {
  return {
    id: p?.id ?? '',
    nodes: Array.isArray(p?.nodes) ? p.nodes.map(mapNode) : [],
    steps: Array.isArray(p?.steps)
      ? p.steps.map((s: any): AttackPathStep => ({ kind: s?.kind ?? '', observed: s?.observed ?? false, toFinding: s?.toFinding ?? s?.to_finding ?? false }))
      : [],
    uncertainties: Array.isArray(p?.uncertainties) ? p.uncertainties : [],
    confident: p?.confident ?? false,
  }
}

export const attackPathApi = {
  // Returns [] when the attack-path feature is disabled (the route answers empty rather than 404).
  listAttackPaths: async (filters: AttackPathFilters = {}): Promise<AttackPathResult> => {
    const qs = new URLSearchParams()
    if (filters.target) qs.set('target', filters.target)
    if (filters.entrypoint) qs.set('entrypoint', filters.entrypoint)
    if (filters.finding) qs.set('finding', filters.finding)
    const q = qs.toString()
    const r = await req(`/attack-paths${q ? `?${q}` : ''}`)
    return {
      paths: Array.isArray(r?.paths) ? r.paths.map(mapPath) : [],
      truncated: r?.bounds?.truncated ?? false,
    }
  },
}
