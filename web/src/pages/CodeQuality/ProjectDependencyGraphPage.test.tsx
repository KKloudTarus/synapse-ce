import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { createMemoryRouter, Outlet, RouterProvider } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { Project, ProjectDependencyGraph } from '../../lib/types'
import { ProjectDependencyGraphPage } from './ProjectDependencyGraphPage'

vi.mock('../../lib/api', () => ({
  api: {
    projectBranches: vi.fn(() => Promise.resolve([])),
    projectDependencyGraph: vi.fn(),
    downloadProjectDependencySubtree: vi.fn(),
  },
}))

const graph: ProjectDependencyGraph = {
  analysisId: 'analysis-1',
  roots: ['app'],
  nodes: [
    dependency('app', { direct: true, depth: 0 }),
    dependency('logging', { depth: 1 }),
    dependency('log4j-core', {
      depth: 2,
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      licenseRisk: true,
      licenseVerdict: 'warn',
      licenses: [{ id: 'Apache-2.0', name: '', category: 'permissive' }],
      vulnerabilityCount: 1,
      worstSeverity: 'critical',
      vulnerabilities: [{ id: 'CVE-2021-44228', source: 'nvd', severity: 'critical', fixedVersion: '2.17.1' }],
    }),
  ],
  edges: [{ from: 'app', to: 'logging' }, { from: 'logging', to: 'log4j-core' }],
  summary: { components: 3, direct: 1, transitive: 2, vulnerable: 1, licenseRisk: 1, edges: 2 },
}

const project: Project = {
  id: 'project-1',
  key: 'payments',
  name: 'Payments',
  sourceBinding: { kind: 'git', value: 'https://example.test/payments.git', ref: 'main' },
  defaultProfileByLang: {},
  gateId: '',
  createdAt: null,
  latestAnalysis: {} as Project['latestAnalysis'],
  latestJob: null,
}

describe('ProjectDependencyGraphPage', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.projectDependencyGraph).mockResolvedValue(graph)
    vi.mocked(api.downloadProjectDependencySubtree).mockResolvedValue()
  })

  it('explores reverse paths and package risk without fetching the full scan result', async () => {
    renderPage()
    expect(await screen.findByText('Dependency explorer')).toBeInTheDocument()
    expect(api.projectDependencyGraph).toHaveBeenCalledWith('payments', expect.any(AbortSignal))

    fireEvent.change(screen.getByPlaceholderText('Find a package, version, or PURL…'), { target: { value: 'log4j' } })
    const match = screen.getByText('1 package match')
    fireEvent.click(within(match.parentElement as HTMLElement).getByRole('button', { name: /log4j-core/ }))

    expect(await screen.findByText('CVE-2021-44228')).toBeInTheDocument()
    expect(screen.getByText('Paths to this package (1)')).toBeInTheDocument()
    expect(screen.getByText('Fixed in 2.17.1', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('Apache-2.0', { exact: false })).toBeInTheDocument()
  })

  it('exports the selected package as a filtered CycloneDX subtree', async () => {
    renderPage()
    expect(await screen.findByText('Dependency explorer')).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('Find a package, version, or PURL…'), { target: { value: 'log4j' } })
    fireEvent.click(screen.getAllByRole('button', { name: /log4j-core/ })[0])
    fireEvent.click(screen.getByRole('button', { name: 'Subtree' }))
    await waitFor(() => expect(api.downloadProjectDependencySubtree).toHaveBeenCalledWith('payments', 'log4j-core'))
  })

  it('keeps vulnerable ancestors in the filtered tree', async () => {
    renderPage()
    expect(await screen.findByText('Dependency explorer')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Vulnerable' }))
    expect(screen.getByText('3 shown')).toBeInTheDocument()
    expect(screen.getAllByText('app').length).toBeGreaterThan(0)
    expect(screen.getAllByText('logging').length).toBeGreaterThan(0)
  })
})

function dependency(id: string, overrides: Partial<ProjectDependencyGraph['nodes'][number]> = {}): ProjectDependencyGraph['nodes'][number] {
  return {
    id,
    name: id,
    version: '1.0.0',
    purl: `pkg:npm/${id}@1.0.0`,
    scope: 'required',
    reachability: 'unknown',
    direct: false,
    depth: 1,
    licenses: [],
    licenseRisk: false,
    licenseVerdict: '',
    vulnerabilities: [],
    vulnerabilityCount: 0,
    worstSeverity: '',
    ...overrides,
  }
}

function ProjectShell() {
  return <Outlet context={{ projectKey: 'payments', project, job: null, isRunning: false, operationError: null, analysisRevision: 0 }} />
}

function renderPage() {
  const router = createMemoryRouter([{
    path: '/projects/:key',
    element: <ProjectShell />,
    children: [{ path: 'dependencies', element: <ProjectDependencyGraphPage /> }],
  }], { initialEntries: ['/projects/payments/dependencies'] })
  render(<RouterProvider router={router} />)
}
