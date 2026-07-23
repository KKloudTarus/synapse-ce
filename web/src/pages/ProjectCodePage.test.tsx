import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ProjectCodePage } from './ProjectCodePage'

let context = { projectKey: 'project', analysisRevision: 0, isRunning: false }

vi.mock('../lib/api', () => ({ api: {
  projectAnalyses: vi.fn(),
  listProjectCodeFiles: vi.fn(),
  projectCodeFile: vi.fn(),
  projectCodeDiff: vi.fn(),
}, ApiError: class ApiError extends Error {} }))
vi.mock('./CodeQualityProject', () => ({
  ProjectRouteEmpty: () => <div>Empty</div>,
  useProjectRouteContext: () => context,
}))
vi.mock('../components/codequality/ProjectCodeWorkspace', () => ({
  ProjectCodeWorkspace: ({ index, view, onSelectFile, onSelectFinding, onNavigateLine }: { index: { analysisId: string }; view: string; onSelectFile: (path: string) => void; onSelectFinding: (finding: null) => void; onNavigateLine: (line: number) => void }) => <div>Analysis {index.analysisId}<div>View {view}</div><button onClick={() => onSelectFile('unchanged.go')}>Select unchanged</button><button onClick={() => onSelectFinding(null)}>Clear finding</button><button onClick={() => onNavigateLine(1001)}>Next source window</button></div>,
}))

import { api } from '../lib/api'
import type { ProjectCodeFileIndex } from '../lib/types'

const index = (analysisId: string): ProjectCodeFileIndex => ({
  analysisId, base: null, head: { ref: 'main', commit: 'head', artifactDigest: 'sha256:head' },
  capabilities: { source: true, unifiedDiff: true, splitDiff: true, lineCoverage: false },
  files: [
    { path: 'main.go', oldPath: null, status: 'modified' as const, language: 'go', lines: 1, findingCount: 0, changedLineCount: 1, binary: false, generated: false, sourceAvailable: true, sourceReason: null },
    { path: 'unchanged.go', oldPath: null, status: 'unchanged' as const, language: 'go', lines: 1, findingCount: 0, changedLineCount: 0, binary: false, generated: false, sourceAvailable: true, sourceReason: null },
  ],
})

function Location() { return <div data-testid="location">{useLocation().search}</div> }

function renderPage(initialEntry = '/code') {
  return render(<MemoryRouter initialEntries={[initialEntry]}><ProjectCodePage /><Location /></MemoryRouter>)
}

describe('ProjectCodePage', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    context = { projectKey: 'project', analysisRevision: 0, isRunning: false }
    vi.mocked(api.listProjectCodeFiles).mockImplementation(async (_key, analysisId) => index(analysisId))
    vi.mocked(api.projectCodeFile).mockResolvedValue({} as never)
    vi.mocked(api.projectCodeDiff).mockResolvedValue({} as never)
  })

  it('follows latest without adding an analysis query', async () => {
    vi.mocked(api.projectAnalyses).mockResolvedValueOnce({ items: [{ id: 'latest-1' }] } as never)
    renderPage('/code')
    expect(await screen.findByText('Analysis latest-1')).toBeInTheDocument()
    expect(screen.getByTestId('location')).not.toHaveTextContent('analysis=')
  })

  it('keeps an explicit analysis query pinned', async () => {
    renderPage('/code?analysis=pinned')
    expect(await screen.findByText('Analysis pinned')).toBeInTheDocument()
    expect(api.projectAnalyses).not.toHaveBeenCalled()
    expect(screen.getByTestId('location')).toHaveTextContent('?analysis=pinned')
  })

  it('uses source for a direct diff URL to an unchanged file', async () => {
    renderPage('/code?analysis=pinned&path=unchanged.go&view=unified&line=1')

    expect(await screen.findByText('View source')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('location')).not.toHaveTextContent('view='))
    expect(screen.getByTestId('location')).toHaveTextContent('analysis=pinned')
    expect(screen.getByTestId('location')).toHaveTextContent('path=unchanged.go')
    expect(api.projectCodeFile).toHaveBeenCalledWith('project', 'pinned', 'unchanged.go', 1, expect.any(AbortSignal))
    expect(api.projectCodeDiff).not.toHaveBeenCalled()
  })

  it('leaves diff mode when switching to an unchanged file', async () => {
    renderPage('/code?analysis=pinned&path=main.go&view=unified')

    expect(await screen.findByText('View unified')).toBeInTheDocument()
    await waitFor(() => expect(api.projectCodeDiff).toHaveBeenCalledWith('project', 'pinned', 'main.go', 'unified', expect.any(AbortSignal)))
    fireEvent.click(screen.getByRole('button', { name: 'Select unchanged' }))

    expect(await screen.findByText('View source')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('location')).not.toHaveTextContent('view='))
    expect(api.projectCodeDiff).not.toHaveBeenCalledWith('project', 'pinned', 'unchanged.go', expect.anything(), expect.anything())
  })

  it('moves to another bounded source window through URL state', async () => {
    renderPage('/code?analysis=pinned&path=main.go&line=1&finding=f1')
    await screen.findByText('Analysis pinned')
    fireEvent.click(screen.getByRole('button', { name: 'Next source window' }))

    await waitFor(() => expect(api.projectCodeFile).toHaveBeenCalledWith('project', 'pinned', 'main.go', 1001, expect.any(AbortSignal)))
    expect(screen.getByTestId('location')).toHaveTextContent('line=1001')
    expect(screen.getByTestId('location')).not.toHaveTextContent('finding=')
  })

  it('preserves the source line when clearing a finding', async () => {
    renderPage('/code?analysis=pinned&path=main.go&line=42&finding=f1')
    await screen.findByText('Analysis pinned')
    fireEvent.click(screen.getByRole('button', { name: 'Clear finding' }))

    await waitFor(() => expect(screen.getByTestId('location')).not.toHaveTextContent('finding='))
    expect(screen.getByTestId('location')).toHaveTextContent('line=42')
    expect(api.projectCodeFile).not.toHaveBeenCalledWith('project', 'pinned', 'main.go', 1001, expect.anything())
  })

  it('falls back to source when the selected diff capability is unavailable', async () => {
    vi.mocked(api.listProjectCodeFiles).mockResolvedValueOnce({ ...index('pinned'), capabilities: { source: true, unifiedDiff: false, splitDiff: false, lineCoverage: false } })
    renderPage('/code?analysis=pinned&path=main.go&view=unified')

    expect(await screen.findByText('View source')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('location')).not.toHaveTextContent('view='))
    expect(api.projectCodeDiff).not.toHaveBeenCalled()
  })

  it('reloads latest after analysis revision changes', async () => {
    vi.mocked(api.projectAnalyses)
      .mockResolvedValueOnce({ items: [{ id: 'latest-1' }] } as never)
      .mockResolvedValueOnce({ items: [{ id: 'latest-2' }] } as never)
    const view = renderPage('/code')
    expect(await screen.findByText('Analysis latest-1')).toBeInTheDocument()
    context = { ...context, analysisRevision: 1 }
    view.rerender(<MemoryRouter initialEntries={['/code']}><ProjectCodePage /><Location /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('Analysis latest-2')).toBeInTheDocument())
    expect(screen.getByTestId('location')).not.toHaveTextContent('analysis=')
  })
})
