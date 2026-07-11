import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Boxes, GitFork, Network, Scale, Search, ShieldAlert } from 'lucide-react'
import { useMemo, useState, type CSSProperties } from 'react'
import { Card, cn, EmptyState, Input, Select } from '../components/ui'
import type { ScanResult, Severity, Vulnerability } from '../lib/types'

const MAX_NODES = 300

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const SEV_ABBR: Record<string, string> = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' }
const sevRank = (s: string) => SEV_RANK[s] ?? 0
const sevToken = (s?: Severity) => (s && SEV_RANK[s] ? (s === 'info' ? 'infosev' : s) : 'border')

// componentID mirrors the backend identity (purl, else name@version).
function componentID(name: string, version: string, purl: string) {
  if (purl) return purl
  return version ? `${name}@${version}` : name
}

function shortName(name: string) {
  const seg = name.split('/').filter(Boolean)
  return seg.length ? seg[seg.length - 1] : name
}

function nodeStyle(sev: Severity | undefined, focus: boolean): CSSProperties {
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

// layered assigns each node a depth (distance from a node nothing depends on),
// giving a left-to-right DAG layout. Cycle-safe via a visited set.
function layered(ids: string[], edges: Array<{ source: string; target: string }>): Map<string, number> {
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

interface NodeMeta {
  name: string
  version: string
  label: string
  sev?: Severity
}

interface GraphIndex {
  meta: Map<string, NodeMeta>
  children: Map<string, string[]>
  parents: Map<string, string[]>
  nameIndex: Array<{ id: string; name: string; version: string }>
  cvToId: Map<string, string>
  vulnsById: Map<string, Vulnerability[]>
  totalComponents: number
  totalEdges: number
}

function buildIndex(scan: ScanResult): GraphIndex {
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
function resolveToId(idx: GraphIndex, token: string): string | null {
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

interface SubGraph {
  ids: Set<string>
  edges: Array<{ source: string; target: string }>
  focus: string | null
  note?: string
}

const EMPTY_SUB: SubGraph = { ids: new Set(), edges: [], focus: null }

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
function findingPathGraph(idx: GraphIndex, v: Vulnerability): SubGraph {
  const compId = idx.cvToId.get(`${v.component}|${v.version}`)
  // Keep the full backend path; toFlow falls back to shortName for any node that
  // lacks SBOM metadata, so the chain never silently breaks.
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
function explorerGraph(idx: GraphIndex, focusId: string, depth: number): SubGraph {
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
function pathToRoot(idx: GraphIndex, start: string): string[] {
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
function licensePathGraph(idx: GraphIndex, id: string): SubGraph {
  const chain = pathToRoot(idx, id)
  return { ids: new Set(chain), edges: chainEdges(chain), focus: id }
}

// Mode 4 – Blast Radius: every package that (transitively) depends on a component.
function blastRadiusGraph(idx: GraphIndex, focusId: string): SubGraph {
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

function toFlow(idx: GraphIndex, sub: SubGraph): { nodes: Node[]; edges: Edge[] } {
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

// ---- UI ----

type Mode = 'finding' | 'explorer' | 'license' | 'blast'

const MODES: { id: Mode; label: string; icon: typeof Network; hint: string }[] = [
  { id: 'finding', label: 'Finding path', icon: ShieldAlert, hint: 'Why does this finding exist?' },
  { id: 'explorer', label: 'Package explorer', icon: Search, hint: 'Parents, children, and risk of a package.' },
  { id: 'license', label: 'License path', icon: Scale, hint: 'Why is this license here?' },
  { id: 'blast', label: 'Blast radius', icon: GitFork, hint: 'What depends on this package?' },
]

export function DependencyGraphTab({ scan }: { scan: ScanResult | null }) {
  const idx = useMemo(() => (scan ? buildIndex(scan) : null), [scan])
  const [mode, setMode] = useState<Mode>('finding')
  const [vulnIdx, setVulnIdx] = useState(0)
  const [focusId, setFocusId] = useState<string | null>(null)
  const [depth, setDepth] = useState(2)
  const [licId, setLicId] = useState<string | null>(null)

  // Flagged-license components (deny/warn or copyleft) → path targets.
  const licenseOptions = useMemo(() => {
    if (!scan || !idx) return []
    const out: { value: string; label: string }[] = []
    const seen = new Set<string>()
    for (const l of scan.licenses) {
      const flagged = l.verdict !== 'allow' || l.category === 'copyleft' || l.category === 'weak-copyleft'
      if (!flagged) continue
      for (const c of l.components) {
        const id = resolveToId(idx, c)
        if (!id || seen.has(id)) continue
        seen.add(id)
        out.push({ value: id, label: `${l.license} · ${shortName(idx.meta.get(id)?.name ?? c)}` })
      }
    }
    return out
  }, [scan, idx])

  const effLic = licId ?? licenseOptions[0]?.value ?? null

  const sub = useMemo<SubGraph>(() => {
    if (!idx || !scan) return EMPTY_SUB
    switch (mode) {
      case 'finding':
        return scan.vulnerabilities[vulnIdx] ? findingPathGraph(idx, scan.vulnerabilities[vulnIdx]) : EMPTY_SUB
      case 'explorer':
        return focusId && idx.meta.has(focusId) ? explorerGraph(idx, focusId, depth) : EMPTY_SUB
      case 'license':
        return effLic && idx.meta.has(effLic) ? licensePathGraph(idx, effLic) : EMPTY_SUB
      case 'blast':
        return focusId && idx.meta.has(focusId) ? blastRadiusGraph(idx, focusId) : EMPTY_SUB
    }
  }, [idx, scan, mode, vulnIdx, focusId, depth, effLic])

  const capped = sub.ids.size > MAX_NODES
  const flow = useMemo(() => (idx && sub.ids.size > 0 && !capped ? toFlow(idx, sub) : null), [idx, sub, capped])

  if (!scan || !idx) {
    return <EmptyState icon={Boxes} title="No scan yet" hint="Run a scan above to explore dependency paths." />
  }

  const focusMeta = sub.focus ? idx.meta.get(sub.focus) : null
  const focusVulns = sub.focus ? idx.vulnsById.get(sub.focus) ?? [] : []
  const selectedVuln = scan.vulnerabilities[vulnIdx]

  return (
    <Card bodyClass="p-0">
      {/* Mode switcher – the graph answers a question, it is not a full dump. */}
      <div className="flex flex-wrap gap-1.5 border-b border-border p-3">
        {MODES.map((m) => {
          const active = mode === m.id
          return (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              title={m.hint}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
                active ? 'bg-brand/15 text-branddim ring-1 ring-inset ring-brand/30' : 'text-mutedfg hover:bg-elevated hover:text-foreground',
              )}
            >
              <m.icon className="size-4" />
              {m.label}
            </button>
          )
        })}
      </div>

      {/* Per-mode controls + context. */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        {mode === 'finding' &&
          (scan.vulnerabilities.length === 0 ? (
            <span className="text-sm text-mutedfg">No vulnerabilities to trace.</span>
          ) : (
            <>
              <Select
                value={String(vulnIdx)}
                onValueChange={(v) => setVulnIdx(Number(v))}
                ariaLabel="Finding to trace"
                className="min-w-[18rem] max-w-full"
                options={scan.vulnerabilities.map((v, i) => ({
                  value: String(i),
                  label: `${v.severity.toUpperCase()} · ${v.id} · ${shortName(v.component)}`,
                }))}
              />
              {selectedVuln && (
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-xs text-mutedfg">
                  <KV label="CVSS" value={selectedVuln.cvssScore > 0 ? selectedVuln.cvssScore.toFixed(1) : '–'} />
                  <KV label="current" value={`${selectedVuln.component}@${selectedVuln.version}`} />
                  <KV
                    label="fixed in"
                    value={selectedVuln.fixedVersion || '–'}
                    valueClass={selectedVuln.fixedVersion ? 'text-accent' : 'text-subtlefg'}
                  />
                </div>
              )}
            </>
          ))}

        {(mode === 'explorer' || mode === 'blast') && (
          <>
            <ComponentPicker idx={idx} value={focusId} onPick={setFocusId} />
            {mode === 'explorer' && (
              <Select
                value={String(depth)}
                onValueChange={(v) => setDepth(Number(v))}
                ariaLabel="Explore depth"
                size="sm"
                options={[1, 2, 3].map((d) => ({ value: String(d), label: `depth ${d}` }))}
              />
            )}
            {focusMeta && (
              <span className="font-mono text-xs tabular-nums text-mutedfg">
                {mode === 'blast' ? `${sub.ids.size - 1} dependent package(s)` : `${sub.ids.size} package(s) in view`}
                {focusVulns.length > 0 && <span className="text-high"> · {focusVulns.length} finding(s)</span>}
              </span>
            )}
          </>
        )}

        {mode === 'license' &&
          (licenseOptions.length === 0 ? (
            <span className="text-sm text-mutedfg">No flagged-license packages in this scan.</span>
          ) : (
            <>
              <Select
                value={effLic ?? ''}
                onValueChange={setLicId}
                ariaLabel="Flagged-license component"
                className="min-w-[18rem] max-w-full"
                options={licenseOptions}
              />
              {focusMeta && (
                <span className="text-xs text-mutedfg">
                  Why <span className="font-mono text-foreground">{focusMeta.name}</span> is here.
                </span>
              )}
            </>
          ))}
      </div>

      <GraphCanvas
        idx={idx}
        sub={sub}
        flow={flow}
        capped={capped}
        mode={mode}
        hasSelection={mode === 'explorer' || mode === 'blast' ? !!focusId : true}
      />
    </Card>
  )
}

function GraphCanvas({
  idx,
  sub,
  flow,
  capped,
  mode,
  hasSelection,
}: {
  idx: GraphIndex
  sub: SubGraph
  flow: { nodes: Node[]; edges: Edge[] } | null
  capped: boolean
  mode: Mode
  hasSelection: boolean
}) {
  if (capped) {
    return (
      <Centered>
        <Network className="size-7 text-subtlefg" />
        <p className="max-w-md text-sm text-mutedfg">
          This repository contains {idx.totalComponents.toLocaleString()} packages and{' '}
          {idx.totalEdges.toLocaleString()} dependency edges – too large to render at once. Narrow the depth, or use{' '}
          <span className="text-foreground">Finding path</span> / <span className="text-foreground">License path</span>{' '}
          to explore a focused chain.
        </p>
      </Centered>
    )
  }
  if (!hasSelection) {
    return (
      <Centered>
        <Search className="size-7 text-subtlefg" />
        <p className="text-sm text-mutedfg">
          {mode === 'explorer' ? 'Search for a component to see its parents and children.' : 'Search for a component to see its blast radius.'}
        </p>
      </Centered>
    )
  }
  if (!flow || flow.nodes.length === 0) {
    return (
      <Centered>
        <Boxes className="size-7 text-subtlefg" />
        <p className="text-sm text-mutedfg">No dependency relationships recorded for this selection.</p>
      </Centered>
    )
  }
  return (
    <>
      {sub.note && <div className="border-b border-border px-4 py-2 text-xs text-mutedfg">{sub.note}</div>}
      <div className="bg-bg" style={{ height: 540 }}>
        <ReactFlow
          nodes={flow.nodes}
          edges={flow.edges}
          fitView
          minZoom={0.1}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="var(--color-border)" gap={22} />
          <Controls showInteractive={false} />
          {flow.nodes.length > 40 && (
            <MiniMap pannable zoomable style={{ background: 'var(--color-surface)' }} maskColor="rgba(0,0,0,0.5)" />
          )}
        </ReactFlow>
      </div>
    </>
  )
}

function ComponentPicker({
  idx,
  value,
  onPick,
}: {
  idx: GraphIndex
  value: string | null
  onPick: (id: string) => void
}) {
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const meta = value ? idx.meta.get(value) : null
  const matches = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return []
    return idx.nameIndex.filter((n) => n.name.toLowerCase().includes(s)).slice(0, 8)
  }, [q, idx])

  const showList = q.trim().length > 0
  const act = matches.length ? Math.min(active, matches.length - 1) : 0

  function commit(i: number) {
    const m = matches[i]
    if (!m) return
    onPick(m.id)
    setQ('')
    setActive(0)
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Escape') {
      setQ('')
      setActive(0)
      return
    }
    if (!matches.length) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive(Math.min(act + 1, matches.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive(Math.max(act - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      commit(act)
    }
  }

  return (
    <div className="relative w-72 max-w-full">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-subtlefg" />
        <Input
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setActive(0)
          }}
          onKeyDown={onKeyDown}
          role="combobox"
          aria-expanded={showList}
          aria-controls="component-picker-list"
          aria-autocomplete="list"
          aria-activedescendant={matches.length ? `cp-opt-${act}` : undefined}
          placeholder={meta ? `${meta.name}@${meta.version}` : 'Search a component…'}
          aria-label="Search a component"
          className="h-9 pl-8 font-mono text-xs"
        />
      </div>
      {showList && (
        <ul
          id="component-picker-list"
          role="listbox"
          className="absolute z-20 mt-1 max-h-64 w-full overflow-auto rounded-lg border border-border bg-card p-1 shadow-lg"
        >
          {matches.length === 0 ? (
            <li className="px-2 py-1.5 text-xs text-mutedfg">No packages match &ldquo;{q.trim()}&rdquo;.</li>
          ) : (
            matches.map((m, i) => (
              <li key={m.id} id={`cp-opt-${i}`} role="option" aria-selected={i === act}>
                <button
                  onClick={() => commit(i)}
                  onMouseEnter={() => setActive(i)}
                  tabIndex={-1}
                  className={cn(
                    'flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-xs transition-colors',
                    i === act ? 'bg-elevated' : 'hover:bg-elevated',
                  )}
                >
                  <span className="truncate font-mono text-foreground">{m.name}</span>
                  <span className="shrink-0 font-mono tabular-nums text-subtlefg">{m.version}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  )
}

function KV({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-[11px] uppercase tracking-wide text-subtlefg">{label}</span>
      <span className={cn('text-foreground tabular-nums', valueClass)}>{value}</span>
    </span>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="flex h-[540px] flex-col items-center justify-center gap-3 px-6 text-center">{children}</div>
}
