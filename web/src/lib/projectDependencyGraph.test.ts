import { describe, expect, it } from 'vitest'
import type { ProjectDependencyGraph, ProjectDependencyNode } from './types'
import {
  allPathsToDependency,
  buildProjectDependencyIndex,
  countDescendants,
  projectDependencyTreeRows,
  visibleDependencyIDs,
  vulnerablePathIDs,
} from './projectDependencyGraph'

function node(id: string, overrides: Partial<ProjectDependencyNode> = {}): ProjectDependencyNode {
  return {
    id,
    name: id,
    version: '1.0.0',
    purl: `pkg:npm/${id}@1.0.0`,
    scope: 'required',
    reachability: '',
    direct: id === 'app',
    depth: 0,
    licenses: [],
    licenseRisk: false,
    licenseVerdict: '',
    vulnerabilities: [],
    vulnerabilityCount: 0,
    worstSeverity: '',
    ...overrides,
  }
}

function graph(): ProjectDependencyGraph {
  return {
    analysisId: 'analysis-1',
    roots: ['app'],
    nodes: [node('app'), node('left'), node('right'), node('shared', { vulnerabilityCount: 1, worstSeverity: 'high' })],
    edges: [
      { from: 'app', to: 'left' },
      { from: 'app', to: 'right' },
      { from: 'left', to: 'shared' },
      { from: 'right', to: 'shared' },
    ],
    summary: { components: 4, direct: 1, transitive: 3, vulnerable: 1, licenseRisk: 0, edges: 4 },
  }
}

describe('project dependency graph traversal', () => {
  it('finds every reverse path through a DAG', () => {
    const index = buildProjectDependencyIndex(graph())
    expect(allPathsToDependency(index, 'shared').paths).toEqual([
      ['app', 'left', 'shared'],
      ['app', 'right', 'shared'],
    ])
    expect(countDescendants(index, 'app')).toBe(3)
  })

  it('keeps ancestors visible while filtering', () => {
    const index = buildProjectDependencyIndex(graph())
    expect([...visibleDependencyIDs(index, 'vulnerable', '')].sort()).toEqual(['app', 'left', 'right', 'shared'])
    expect([...vulnerablePathIDs(index)].sort()).toEqual(['app', 'left', 'right', 'shared'])
  })

  it('terminates on cycles and exposes an inferred display root', () => {
    const cyclic = graph()
    cyclic.roots = []
    cyclic.edges = [{ from: 'left', to: 'right' }, { from: 'right', to: 'left' }]
    cyclic.nodes = [node('left'), node('right')]
    const index = buildProjectDependencyIndex(cyclic)
    expect(index.roots).toEqual(['left'])
    expect(allPathsToDependency(index, 'right').paths).toEqual([['left', 'right']])
  })

  it('keeps a disconnected cycle visible beside ordinary roots', () => {
    const mixed = graph()
    mixed.nodes.push(node('cycle-a', { depth: -1 }), node('cycle-b', { depth: -1 }))
    mixed.edges.push({ from: 'cycle-a', to: 'cycle-b' }, { from: 'cycle-b', to: 'cycle-a' })
    const index = buildProjectDependencyIndex(mixed)
    expect(index.roots).toEqual(['app', 'cycle-a'])
  })

  it('caps path enumeration explicitly', () => {
    const index = buildProjectDependencyIndex(graph())
    expect(allPathsToDependency(index, 'shared', 1)).toEqual({ paths: [['app', 'left', 'shared']], truncated: true })
  })

  it('renders shared DAG nodes once and bounds large trees', () => {
    const index = buildProjectDependencyIndex(graph())
    const all = new Set(index.nodes.keys())
    const expanded = new Set(index.nodes.keys())
    const complete = projectDependencyTreeRows(index, all, expanded)
    expect(complete.rows.map((row) => row.id)).toEqual(['app', 'left', 'shared', 'right'])
    expect(complete.truncated).toBe(false)
    expect(projectDependencyTreeRows(index, all, expanded, 2)).toMatchObject({ truncated: true, rows: [{ id: 'app' }, { id: 'left' }] })
  })
})
