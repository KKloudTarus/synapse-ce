import type { CSSProperties } from 'react'
import type { Edge, Node } from '@xyflow/react'
import type { ScanResult, Severity, Vulnerability } from './types'

export const MAX_NODES = 300

export const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
export const SEV_ABBR: Record<string, string> = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' }
export const sevRank = (s: string) => SEV_RANK[s] ?? 0
export const sevToken = (s?: Severity) => (s && SEV_RANK[s] ? (s === 'info' ? 'infosev' : s) : 'border')

// componentID mirrors the backend identity (purl, else name@version).
export function componentID(name: string, version: string, purl: string) {
  if (purl) return purl
  return version ? `${name}@${version}` : name
}

export function shortName(name: string) {
  const seg = name.split('/').filter(Boolean)
  return seg.length ? seg[seg.length - 1] : name
}

// layered assigns each node a depth (distance from a node nothing depends on),
// giving a left-to-right DAG layout. Cycle-safe via a visited set.
export function layered(ids: string[], edges: Array<{ source: string; target: string }>): Map<string, number> {
  const adj = new Map<string, string[]>()
  const indeg = new Map<string, number>()
  ids.forEach((id) => indeg.set(id, 0))
  for (const { source, target } of edges) {
    if (!adj.has(source)) adj.set(source, [])
    adj.get(source)!.push(target)
    indeg.set(target, (indeg.get(target) ?? 0) + 1)
  }
  const level = new Map<string, number>(ids.map((id) => [id, 0]))
  const queue = ids.filter((id) => (indeg.get(id) ?? 0) === 0)
  const seen = new Set(queue)
  while (queue.length) {
    const n = queue.shift()!
    for (const m of adj.get(n) ?? []) {
      level.set(m, Math.max(level.get(m) ?? 0, (level.get(n) ?? 0) + 1))
      if (!seen.has(m)) {
        seen.add(m)
        queue.push(m)
      }
    }
  }
  return level
}

// ---- index ----

export interface NodeMeta {
  name: string
  version: string
  label: string
  sev?: Severity
}

export interface GraphIndex {
  meta: Map<string, NodeMeta>
  children: Map<string, string[]>
  parents: Map<string, string[]>
  nameIndex: Array<{ id: string; name: string; version: string }>
  cvToId: Map<string, string>
  vulnsById: Map<string, Vulnerability[]>
  totalComponents: number
  totalEdges: number
}

export function buildIndex(scan: ScanResult): GraphIndex {
  const worstSev = new Map<string, Severity>()
  const vulnsByCV = new Map<string, Vulnerability[]>()
  for (const v of scan.vulnerabilities) {
    const k = `${v.component}|${v.version}`
    const cur = worstSev.get(k)
    if (!cur || sevRank(v.severity) > sevRank(cur)) worstSev.set(k, v.severity)
    if (!vulnsByCV.has(k)) vulnsByCV.set(k, [])
    vulnsByCV.get(k)!.push(v)
  }

  const meta = new Map<string, NodeMeta>()
  const cvToId = new Map<string, string>()
  const vulnsById = new Map<string, Vulnerability[]>()
  const nameIndex: GraphIndex['nameIndex'] = []
  for (const c of scan.components) {
    const id = componentID(c.name, c.version, c.purl)
    const cv = `${c.name}|${c.version}`
    meta.set(id, { name: c.name, version: c.version, label: shortName(c.name), sev: worstSev.get(cv) })
    if (!cvToId.has(cv)) cvToId.set(cv, id)
    nameIndex.push({ id, name: c.name, version: c.version })
    const vs = vulnsByCV.get(cv)
    if (vs) vulnsById.set(id, vs)
  }

  const children = new Map<string, string[]>()
  const parents = new Map<string, string[]>()
  let totalEdges = 0
  for (const d of scan.dependencies) {
    for (const t of d.dependsOn) {
      if (!meta.has(d.ref) || !meta.has(t)) continue
      ;(children.get(d.ref) ?? children.set(d.ref, []).get(d.ref)!).push(t)
      ;(parents.get(t) ?? parents.set(t, []).get(t)!).push(d.ref)
      totalEdges++
    }
  }

  return { meta, children, parents, nameIndex, cvToId, vulnsById, totalComponents: meta.size, totalEdges }
}

// resolveToId maps a license-finding component token (name or name@version) to a node id.
export function resolveToId(idx: GraphIndex, token: string): string | null {
  if (idx.meta.has(token)) return token
  const at = token.lastIndexOf('@')
  if (at > 0) {
    const id = idx.cvToId.get(`${token.slice(0, at)}|${token.slice(at + 1)}`)
    if (id) return id
  }
  const hit = idx.nameIndex.find((n) => n.name === token)
  return hit ? hit.id : null
}

// ---- subgraph builders ----

export interface SubGraph {
  ids: Set<string>
  edges: Array<{ source: string; target: string }>
  focus: string | null
  note?: string
}

export const EMPTY_SUB: SubGraph = { ids: new Set(), edges: [], focus: null }

function edgesWithin(idx: GraphIndex, ids: Set<string>): Array<{ source: string; target: string }> {
  const out: Array<{ source: string; target: string }> = []
  for (const s of ids) for (const t of idx.children.get(s) ?? []) if (ids.has(t)) out.push({ source: s, target: t })
  return out
}

function chainEdges(chain: string[]): Array<{ source: string; target: string }> {
  const out: Array<{ source: string; target: string }> = []
  for (let i = 0; i < chain.length - 1; i++) out.push({ source: chain[i], target: chain[i + 1] })
  return out
}

// Mode 1 – Finding Path: root → … → vulnerable component (uses the backend path).
export function findingPathGraph(idx: GraphIndex, v: Vulnerability): SubGraph {
  const compId = idx.cvToId.get(`${v.component}|${v.version}`)
  let chain = v.path ?? []
  if (chain.length === 0) chain = compId ? [compId] : []
  if (chain.length === 0) return EMPTY_SUB
  return {
    ids: new Set(chain),
    edges: chainEdges(chain),
    focus: chain[chain.length - 1],
    note: v.direct || chain.length <= 1 ? 'Direct dependency of the project.' : undefined,
  }
}

// Mode 2 – Package Explorer: parents + children of a package up to depth N.
export function explorerGraph(idx: GraphIndex, focusId: string, depth: number): SubGraph {
  const ids = new Set<string>([focusId])
  let frontier = [focusId]
  for (let d = 0; d < depth && frontier.length; d++) {
    const next: string[] = []
    for (const id of frontier) {
      for (const c of idx.children.get(id) ?? [])
        if (!ids.has(c)) {
          ids.add(c)
          next.push(c)
        }
      for (const p of idx.parents.get(id) ?? [])
        if (!ids.has(p)) {
          ids.add(p)
          next.push(p)
        }
    }
    frontier = next
    if (ids.size > MAX_NODES) break
  }
  return { ids, edges: edgesWithin(idx, ids), focus: focusId }
}

// pathToRoot walks UP parents to a project root (BFS, shortest), returning root → start.
export function pathToRoot(idx: GraphIndex, start: string): string[] {
  const prev = new Map<string, string>()
  const seen = new Set([start])
  const queue = [start]
  let root: string | null = null
  while (queue.length) {
    const n = queue.shift()!
    const ps = idx.parents.get(n) ?? []
    if (ps.length === 0) {
      root = n
      break
    }
    for (const p of ps)
      if (!seen.has(p)) {
        seen.add(p)
        prev.set(p, n)
        queue.push(p)
      }
  }
  if (root === null) return [start]
  const path = [root]
  let cur = root
  while (cur !== start) {
    cur = prev.get(cur)!
    path.push(cur)
  }
  return path
}

// Mode 3 – License Path: root → … → the flagged-license component.
export function licensePathGraph(idx: GraphIndex, id: string): SubGraph {
  const chain = pathToRoot(idx, id)
  return { ids: new Set(chain), edges: chainEdges(chain), focus: id }
}

// Mode 4 – Blast Radius: every package that (transitively) depends on a component.
export function blastRadiusGraph(idx: GraphIndex, focusId: string): SubGraph {
  const ids = new Set<string>([focusId])
  let frontier = [focusId]
  while (frontier.length) {
    const next: string[] = []
    for (const id of frontier)
      for (const p of idx.parents.get(id) ?? [])
        if (!ids.has(p)) {
          ids.add(p)
          next.push(p)
        }
    frontier = next
    if (ids.size > MAX_NODES) break
  }
  return { ids, edges: edgesWithin(idx, ids), focus: focusId }
}

// ---- layout → ReactFlow conversion ----

export function nodeStyle(sev: Severity | undefined, focus: boolean): CSSProperties {
  return {
    background: 'var(--color-card)',
    color: 'var(--color-foreground)',
    border: `1px solid var(--color-${focus ? 'brand' : sevToken(sev)})`,
    borderRadius: 8,
    fontSize: 11,
    padding: '6px 10px',
    width: 172,
    boxShadow: focus ? '0 0 0 2px var(--color-brand)' : undefined,
  }
}

export function toFlow(idx: GraphIndex, sub: SubGraph): { nodes: Node[]; edges: Edge[] } {
  const ids = [...sub.ids]
  const level = layered(ids, sub.edges)
  const byLevel = new Map<number, string[]>()
  for (const id of ids) {
    const lv = level.get(id) ?? 0
    ;(byLevel.get(lv) ?? byLevel.set(lv, []).get(lv)!).push(id)
  }
  const nodes: Node[] = []
  for (const [lv, group] of byLevel) {
    group.forEach((id, i) => {
      const m = idx.meta.get(id)
      const label = m ? (m.sev ? `${m.label} · ${SEV_ABBR[m.sev] ?? m.sev}` : m.label) : shortName(id)
      nodes.push({
        id,
        position: { x: lv * 252, y: i * 60 },
        data: { label },
        style: nodeStyle(m?.sev, id === sub.focus),
        connectable: false,
      })
    })
  }
  const edges: Edge[] = sub.edges.map((e, i) => ({
    id: `e${i}`,
    source: e.source,
    target: e.target,
    style: { stroke: 'var(--color-border)', strokeWidth: 1 },
  }))
  return { nodes, edges }
}
