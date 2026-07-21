import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api'
import { CodeQualityProject } from './CodeQualityProject'
import { ProjectMeasuresPage } from './ProjectMeasuresPage'
import type { ProjectMeasureResponse } from '../lib/projectMeasures'

vi.mock('../lib/api', () => ({
  api: {
    getProject: vi.fn(),
    projectAnalysisStatus: vi.fn(),
    projectMeasures: vi.fn(),
    listQualityGates: vi.fn(),
  },
}))

vi.mock('../components/VirtualTable', () => ({
  VirtualTable: ({ items }: any) => (
    <div data-testid="virtual-table">
      {items.map((x: any) => <div key={x.path}>{x.name}</div>)}
    </div>
  )
}))

const project = {
  id: 'project-synapse',
  name: 'Synapse',
  key: 'synapse',
  sourceBinding: { kind: 'git', value: 'https://example.com', ref: 'main' },
  defaultProfileByLang: {},
  gateId: '',
  createdAt: null,
  latestAnalysis: null,
  latestJob: null,
}

function buildResponse(overrides: Partial<ProjectMeasureResponse> = {}): ProjectMeasureResponse {
  return {
    state: 'analyzed',
    project: { key: 'synapse', name: 'Synapse' },
    analysis: { id: 'a1', createdAt: '', sourceRef: '', sourceCommit: '' },
    path: '',
    includedDomains: ['size'],
    node: {
      path: '', name: 'Synapse', kind: 'project', language: '',
      size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null,
    },
    children: { items: [], nextCursor: null },
    ...overrides,
  }
}

describe('Project Measures route and logic', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project as any)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.listQualityGates).mockResolvedValue([])
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse())
  })

  function renderRoute(initialPath: string) {
    const router = createMemoryRouter([
      {
        path: '/code-quality/projects/:key',
        element: <CodeQualityProject />,
        children: [
          { path: 'measures', element: <ProjectMeasuresPage /> },
          { path: '', element: <div>Overview</div> },
          { path: 'issues', element: <div>Issues</div> },
          { path: 'hotspots', element: <div>Hotspots</div> },
          { path: 'analysis', element: <div>Analysis</div> },
          { path: 'activity', element: <div>Activity</div> },
        ],
      },
    ], { initialEntries: [initialPath] })
    render(<RouterProvider router={router} />)
    return router
  }

  it('routing regression test ensures tabs exist and route correctly', async () => {
    const router = renderRoute('/code-quality/projects/synapse/measures')
    
    // Wait for the page to render (Current Node Metrics is in data.node detail panel)
    expect(await screen.findByText('Current Node Metrics')).toBeInTheDocument()
    
    // Tab verification
    const tabs = ['Overview', 'Issues', 'Security Hotspots', 'Measures', 'Analysis details', 'Activity']
    for (const tab of tabs) {
      expect(screen.getByRole('link', { name: tab })).toBeInTheDocument()
    }
    
    // Navigate away
    fireEvent.click(screen.getByRole('link', { name: 'Issues' }))
    await waitFor(() => expect(router.state.location.pathname).toBe('/code-quality/projects/synapse/issues'))
  })

  it('renders project root and not-analyzed state', async () => {
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({ state: 'not_analyzed' }))
    renderRoute('/code-quality/projects/synapse/measures')
    expect(await screen.findByText('No completed analysis yet')).toBeInTheDocument()
  })

  it('directory click changes URL path', async () => {
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({
      children: {
        items: [{ path: 'src', name: 'src', kind: 'directory', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null }],
        nextCursor: null
      }
    }))
    const router = renderRoute('/code-quality/projects/synapse/measures?domain=size')
    await waitFor(() => expect(screen.getAllByText('src').length).toBeGreaterThan(0))
    fireEvent.click(screen.getByRole('button', { name: 'src' }))
    
    await waitFor(() => {
      const search = new URLSearchParams(router.state.location.search)
      expect(search.get('path')).toBe('src')
      expect(search.get('domain')).toBe('size')
    })
  })

  it('breadcrumbs navigate to parent paths and browser back restores path', async () => {
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({
      path: 'src/internal',
    }))
    const router = renderRoute('/code-quality/projects/synapse/measures?path=src%2Finternal&domain=size')
    
    expect(await screen.findByText('internal')).toBeInTheDocument()
    
    fireEvent.click(screen.getByRole('button', { name: 'Synapse' }))
    await waitFor(() => {
      const search = new URLSearchParams(router.state.location.search)
      expect(search.get('path')).toBeNull()
      expect(search.get('domain')).toBe('size')
    })
    
    await act(async () => {
      router.navigate(-1)
    })
    await waitFor(() => {
      const search = new URLSearchParams(router.state.location.search)
      expect(search.get('path')).toBe('src/internal')
      expect(search.get('domain')).toBe('size')
    })
  })

  it('file drill down, node details rendering, and ordering', async () => {
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({
      node: {
        path: 'a.ts', name: 'a.ts', kind: 'file', language: 'ts',
        size: { 
          files: { availability: 'available', value: 1, reason: null },
          ncloc: { availability: 'not_applicable', value: null, reason: null },
          commentLines: { availability: 'not_applicable', value: null, reason: null },
          blankLines: { availability: 'available', value: null, reason: null },
          functions: { availability: 'available', value: 42, reason: null },
          commentDensity: { availability: 'available', value: 0.5, reason: null }
        },
        complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null
      },
      children: {
        items: [],
        nextCursor: null
      }
    }))
    const router = renderRoute('/code-quality/projects/synapse/measures?path=a.ts&domain=size')
    
    // Node metrics panel should render "Current Node Metrics"
    expect(await screen.findByText('Current Node Metrics')).toBeInTheDocument()
    
    // Ensure "Empty directory" is NOT shown for files
    expect(screen.queryByText('Empty directory')).not.toBeInTheDocument()
    
    // Verify file metric details are rendered
    expect(screen.getByText('Lines of Code')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument() // Functions value
    
    // Now simulate clicking a file from a list
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({
      children: {
        items: [
          { path: 'a.ts', name: 'a.ts', kind: 'file', language: 'ts', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null },
          { path: 'dir', name: 'dir', kind: 'directory', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null }
        ],
        nextCursor: null
      }
    }))
    router.navigate('/code-quality/projects/synapse/measures?domain=size')
    
    expect(await screen.findByText('dir')).toBeInTheDocument()
    expect(screen.getByText('a.ts')).toBeInTheDocument()
    
    // Both dir and file should be clickable buttons!
    expect(screen.getByRole('button', { name: 'dir' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'a.ts' })).toBeInTheDocument()
    
    fireEvent.click(screen.getByRole('button', { name: 'a.ts' }))
    await waitFor(() => {
      const search = new URLSearchParams(router.state.location.search)
      expect(search.get('path')).toBe('a.ts')
    })
  })

  it('renders correct severity keys for issues', async () => {
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({
      node: {
        path: '', name: 'Synapse', kind: 'project', language: '', size: null, complexity: null, coverage: null, duplication: null, debt: null, ratings: null,
        issues: {
          byType: {},
          bySeverity: {
            critical: { availability: 'available', value: 5, reason: null },
            high: { availability: 'available', value: 4, reason: null },
            medium: { availability: 'available', value: 3, reason: null },
            low: { availability: 'available', value: 2, reason: null },
            info: { availability: 'available', value: 1, reason: null },
          }
        }
      },
      children: { items: [], nextCursor: null }
    }))
    
    renderRoute('/code-quality/projects/synapse/measures?domain=issues')
    
    expect(await screen.findByText('Current Node Metrics')).toBeInTheDocument()
    
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    
    expect(screen.getByText('Medium')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    
    expect(screen.getByText('Low')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    
    expect(screen.getByText('Info')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
  })

  it('normal load more appends children and deduplicates', async () => {
    vi.mocked(api.projectMeasures).mockResolvedValueOnce(buildResponse({
      children: {
        items: [{ path: '1', name: '1', kind: 'file', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null } as any],
        nextCursor: 'next-page'
      }
    }))
    
    renderRoute('/code-quality/projects/synapse/measures')
    expect(await screen.findByText('1')).toBeInTheDocument()
    
    vi.mocked(api.projectMeasures).mockResolvedValueOnce(buildResponse({
      children: {
        // returning 1 again to test deduplication, and a new item 2
        items: [
          { path: '1', name: '1', kind: 'file', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null } as any,
          { path: '2', name: '2', kind: 'file', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null } as any
        ],
        nextCursor: null
      }
    }))
    
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    
    expect(await screen.findByText('2')).toBeInTheDocument()
    // It should render 1 only once. We can query getAllByText('1') but the breadcrumb and metric might interfere if they are named 1. 
    // The link for '1' is rendered.
    expect(screen.getAllByRole('button', { name: '1' }).length).toBe(1)
  })

  it('stale aborted responses do not replace newer path results or show error', async () => {
    let rejectFirst!: (err: any) => void
    const firstPromise = new Promise((_, rej) => { rejectFirst = rej })
    
    let resolveSecond!: (val: any) => void
    const secondPromise = new Promise(res => { resolveSecond = res })

    // 1. Initial load for path "A"
    vi.mocked(api.projectMeasures).mockResolvedValueOnce(buildResponse({
      path: 'A',
      children: { items: [{ path: 'A/1', name: 'A1', kind: 'file', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null } as any], nextCursor: 'next-A' }
    }))
    
    const router = renderRoute('/code-quality/projects/synapse/measures?path=A&domain=size')
    expect(await screen.findByText('A1')).toBeInTheDocument()

    // 2. Click load more for A (this returns firstPromise which we hold)
    vi.mocked(api.projectMeasures).mockReturnValueOnce(firstPromise as any)
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    
    // 3. While load more is pending, navigate to path "B"
    vi.mocked(api.projectMeasures).mockReturnValueOnce(secondPromise as any)
    act(() => {
      router.navigate('/code-quality/projects/synapse/measures?path=B&domain=size')
    })
    
    // 4. Resolve B
    act(() => {
      resolveSecond(buildResponse({
        path: 'B',
        children: { items: [{ path: 'B/1', name: 'B1', kind: 'file', language: '', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null } as any], nextCursor: null }
      }))
    })
    expect(await screen.findByText('B1')).toBeInTheDocument()
    expect(screen.queryByText('A1')).not.toBeInTheDocument()

    // 5. Now resolve the stale load more for A by throwing AbortError
    act(() => {
      rejectFirst(new DOMException('Aborted', 'AbortError'))
    })

    // Wait a bit to ensure no state updates happen
    await new Promise(r => setTimeout(r, 50))
    
    // Assert only B1 remains, no error state is shown
    expect(screen.getByText('B1')).toBeInTheDocument()
    expect(screen.queryByText('Failed to load more')).not.toBeInTheDocument()
    expect(screen.queryByText('Cannot reach the API')).not.toBeInTheDocument()
  })

  it('renders VirtualTable for >50 rows', async () => {
    const items = Array.from({ length: 60 }).map((_, i) => ({
      path: `f${i}.ts`, name: `f${i}.ts`, kind: 'file', language: 'ts', size: null, complexity: null, coverage: null, duplication: null, issues: null, debt: null, ratings: null
    }))
    
    vi.mocked(api.projectMeasures).mockResolvedValue(buildResponse({
      children: { items: items as any, nextCursor: null }
    }))
    
    renderRoute('/code-quality/projects/synapse/measures?domain=size')
    
    expect(await screen.findByTestId('virtual-table')).toBeInTheDocument()
    expect(screen.getByText('f0.ts')).toBeInTheDocument()
    expect(screen.getByText('f59.ts')).toBeInTheDocument()
    
    // Native table uses table
    expect(screen.queryByRole('columnheader')).not.toBeInTheDocument()
  })
})
