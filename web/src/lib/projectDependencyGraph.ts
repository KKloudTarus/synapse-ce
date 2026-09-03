import type { ProjectDependencyGraph, ProjectDependencyNode } from './types'

export type DependencyFilter = 'all' | 'vulnerable' | 'license-risk' | 'direct' | 'transitive'

export interface ProjectDependencyIndex {
  nodes: Map<string, ProjectDependencyNode>
  children: Map<string, string[]>
  parents: Map<string, string[]>
  roots: string[]
}

export interface DependencyPaths {
  paths: string[][]
  truncated: boolean
}

export interface DependencyTreeRow {
  id: string
  level: number
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right))
}

export function buildProjectDependencyIndex(graph: ProjectDependencyGraph): ProjectDependencyIndex {
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]))
  const children = new Map<string, string[]>()
  const parents = new Map<string, string[]>()

  for (const edge of graph.edges) {
    if (!nodes.has(edge.from) || !nodes.has(edge.to) || edge.from === edge.to) continue
    children.set(edge.from, [...(children.get(edge.from) ?? []), edge.to])
    parents.set(edge.to, [...(parents.get(edge.to) ?? []), edge.from])
  }
  for (const [id, ids] of children) children.set(id, sortedUnique(ids))
  for (const [id, ids] of parents) parents.set(id, sortedUnique(ids))

  const declaredRoots = graph.roots.filter((id) => nodes.has(id))
  const inferredRoots = graph.nodes.filter((node) => !(parents.get(node.id)?.length)).map((node) => node.id)
  const roots = sortedUnique([...declaredRoots, ...inferredRoots])
  const reachable = new Set<string>()
  const queue = [...roots]
  while (queue.length) {
    const id = queue.shift()
    if (!id || reachable.has(id)) continue
    reachable.add(id)
    queue.push(...(children.get(id) ?? []))
  }
  // A valid graph can contain a disconnected rootless cycle. Keep each unreachable region
  // visible behind a synthetic display root; backend depth remains honestly reported as -1.
  for (const candidate of sortedUnique(nodes.keys())) {
    if (reachable.has(candidate)) continue
    roots.push(candidate)
    const unrootedQueue = [candidate]
    while (unrootedQueue.length) {
      const id = unrootedQueue.shift()
      if (!id || reachable.has(id)) continue
      reachable.add(id)
      unrootedQueue.push(...(children.get(id) ?? []))
    }
  }

  return { nodes, children, parents, roots }
}

export function matchesDependencyNode(node: ProjectDependencyNode, filter: DependencyFilter, search: string): boolean {
  const query = search.trim().toLocaleLowerCase()
  const searchable = `${node.name}\n${node.version}\n${node.purl}\n${node.id}`.toLocaleLowerCase()
  if (query && !searchable.includes(query)) return false

  switch (filter) {
    case 'vulnerable': return node.vulnerabilityCount > 0
    case 'license-risk': return node.licenseRisk
    case 'direct': return node.direct
    case 'transitive': return !node.direct
    default: return true
  }
}

export function visibleDependencyIDs(index: ProjectDependencyIndex, filter: DependencyFilter, search: string): Set<string> {
  if (filter === 'all' && !search.trim()) return new Set(index.nodes.keys())

  const visible = new Set<string>()
  const visitParents = (id: string) => {
    if (visible.has(id)) return
    visible.add(id)
    for (const parent of index.parents.get(id) ?? []) visitParents(parent)
  }
  for (const node of index.nodes.values()) {
    if (matchesDependencyNode(node, filter, search)) visitParents(node.id)
  }
  return visible
}

export function vulnerablePathIDs(index: ProjectDependencyIndex): Set<string> {
  const ids = new Set<string>()
  const visitParents = (id: string) => {
    if (ids.has(id)) return
    ids.add(id)
    for (const parent of index.parents.get(id) ?? []) visitParents(parent)
  }
  for (const node of index.nodes.values()) {
    if (node.vulnerabilityCount > 0) visitParents(node.id)
  }
  return ids
}

export function allPathsToDependency(
  index: ProjectDependencyIndex,
  target: string,
  maxPaths = 50,
  maxDepth = 64,
): DependencyPaths {
  if (!index.nodes.has(target)) return { paths: [], truncated: false }
  const paths: string[][] = []
  let truncated = false

  const walk = (id: string, reversed: string[], seen: Set<string>) => {
    if (paths.length >= maxPaths) {
      truncated = true
      return
    }
    if (reversed.length >= maxDepth) {
      truncated = true
      paths.push([...reversed, id].reverse())
      return
    }
    const parentIDs = index.parents.get(id) ?? []
    const availableParents = parentIDs.filter((parent) => !seen.has(parent))
    if (availableParents.length === 0) {
      paths.push([...reversed, id].reverse())
      return
    }
    for (const [parentIndex, parent] of availableParents.entries()) {
      walk(parent, [...reversed, id], new Set([...seen, parent]))
      if (paths.length >= maxPaths) {
        if (parentIndex < availableParents.length - 1) truncated = true
        break
      }
    }
  }

  walk(target, [], new Set([target]))
  return { paths, truncated }
}

export function countDescendants(index: ProjectDependencyIndex, root: string): number {
  const seen = new Set<string>([root])
  const queue = [root]
  while (queue.length) {
    const current = queue.shift()
    if (!current) continue
    for (const child of index.children.get(current) ?? []) {
      if (seen.has(child)) continue
      seen.add(child)
      queue.push(child)
    }
  }
  return Math.max(0, seen.size - 1)
}

export function projectDependencyTreeRows(
  index: ProjectDependencyIndex,
  visible: Set<string>,
  expanded: Set<string>,
  maxRows = 5_000,
): { rows: DependencyTreeRow[]; truncated: boolean } {
  const rows: DependencyTreeRow[] = []
  const emitted = new Set<string>()
  const stack = index.roots.slice().reverse().map((id) => ({ id, level: 0 }))

  while (stack.length > 0 && rows.length < maxRows) {
    const item = stack.pop()
    if (!item || emitted.has(item.id) || !visible.has(item.id)) continue
    emitted.add(item.id)
    rows.push(item)
    if (!expanded.has(item.id)) continue
    const children = index.children.get(item.id) ?? []
    for (let i = children.length - 1; i >= 0; i -= 1) {
      if (visible.has(children[i])) stack.push({ id: children[i], level: item.level + 1 })
    }
  }

  return { rows, truncated: stack.some((item) => visible.has(item.id) && !emitted.has(item.id)) }
}
