import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { createMemoryRouter, Outlet, RouterProvider, useParams } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api'
import type { Project, ProjectAnalysis, ScanJob } from '../lib/types'
import { buildFinding, buildLatestProjectAnalysis } from '../test/projectAnalysisFixtures'
import { buildAnalyzedOverview, buildNotAnalyzedOverview } from '../test/projectOverviewFixtures'
import { CodeQualityProject } from './CodeQualityProject'
import { ProjectActivityPage } from './ProjectActivityPage'
import { ProjectAnalysisPage } from './ProjectAnalysisPage'
import { ProjectOverviewPage } from './ProjectOverviewPage'

vi.mock('../lib/api', () => ({
  api: {
    getProject: vi.fn(),
    projectAnalysisStatus: vi.fn(),
    projectOverview: vi.fn(),
    latestProjectAnalysis: vi.fn(),
    projectAnalyses: vi.fn(),
    listQualityGates: vi.fn(),
    assignProjectGate: vi.fn(),
    startProjectAnalysis: vi.fn(),
  },
}))

const project = buildProject('synapse', 'Synapse')

function buildProject(key: string, name = key): Project {
  return {
  id: `project-${key}`,
  name,
  key,
  sourceBinding: { kind: 'git' as const, value: 'https://example.com/repo.git', ref: 'main' },
  defaultProfileByLang: {},
  gateId: '',
  createdAt: null,
  latestAnalysis: null,
  latestJob: null,
  }
}

function buildJob(id: string, status: ScanJob['status'], error = ''): ScanJob {
  return {
    id,
    engagementId: '',
    target: id,
    kind: 'code-quality',
    status,
    stage: status,
    progress: status === 'running' ? 50 : 100,
    error,
    startedAt: '2026-07-18T00:00:00Z',
    finishedAt: status === 'running' ? null : '2026-07-18T00:01:00Z',
    debugEvents: [],
  }
}

function buildAnalysis(id: string, sourceRef: string): ProjectAnalysis {
  const counts = { total: 1, byKind: {}, bySeverity: {}, byStatus: {} }
  return {
    id,
    createdAt: '2026-07-18T00:00:00Z',
    sourceRef,
    sourceCommit: `${id}abcdef1234567890`,
    gate: { passed: true, results: [] },
    gateInfo: { key: 'synapse-way', name: 'Synapse way', source: 'default' },
    issues: counts,
    newCode: { previousId: 'previous', counts, rating: { security: 'A', reliability: 'A', maintainability: 'A' } },
    delta: null,
    measures: {},
    coverage: null,
    duplication: { blocks: [], duplicatedLines: 0, totalLines: 0, files: 0 },
    rating: { security: 'A', reliability: 'A', maintainability: 'A', techDebtMinutes: 0, debtRatioPct: 0, linesOfCode: 1 },
  }
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

describe('Project Overview routes', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview())
    vi.mocked(api.latestProjectAnalysis).mockResolvedValue(null)
    vi.mocked(api.projectAnalyses).mockResolvedValue({ items: [], next: null })
    vi.mocked(api.listQualityGates).mockResolvedValue([])
  })

  it('loads Overview without fetching the full latest analysis or activity history', async () => {
    renderProjectRoute('/code-quality/projects/synapse')
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()
    expect(api.getProject).toHaveBeenCalledWith('synapse')
    expect(api.projectAnalysisStatus).toHaveBeenCalledWith('synapse')
    expect(api.projectOverview).toHaveBeenCalledWith('synapse')
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
    expect(api.projectAnalyses).not.toHaveBeenCalled()
  })

  it('renders the not-analyzed state without fake metric cards', async () => {
    vi.mocked(api.projectOverview).mockResolvedValue(buildNotAnalyzedOverview())
    renderProjectRoute('/code-quality/projects/synapse')
    expect(await screen.findByText('No completed analysis yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run first analysis' })).toBeInTheDocument()
    expect(screen.queryByText('Quality metrics')).not.toBeInTheDocument()
  })

  it('synchronizes the lens with the URL without refetching Overview', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse?foo=bar&lens=bad')
    await waitFor(() => expect(router.state.location.search).toBe('?foo=bar&lens=overall'))
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()
    expect(api.projectOverview).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'New Code' }))
    expect(router.state.location.search).toBe('?foo=bar&lens=new-code')
    expect(screen.getAllByText('Changed-line metrics are not available for this analysis.').length).toBeGreaterThan(0)
    expect(api.projectOverview).toHaveBeenCalledTimes(1)
  })

  it('keeps the shell visible and retries only Overview on route-local errors', async () => {
    vi.mocked(api.projectOverview).mockRejectedValueOnce(new Error('overview offline')).mockResolvedValueOnce(buildAnalyzedOverview())
    renderProjectRoute('/code-quality/projects/synapse')
    expect(await screen.findByRole('heading', { name: 'Synapse' })).toBeInTheDocument()
    expect(await screen.findByText('overview offline')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry Overview' }))
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()
    expect(api.projectOverview).toHaveBeenCalledTimes(2)
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
  })

  it('preserves Quality Gate assignment on the Project shell', async () => {
    vi.mocked(api.listQualityGates).mockResolvedValue([{ key: 'strict', name: 'Strict', conditions: [], builtIn: false }])
    vi.mocked(api.assignProjectGate).mockResolvedValue({ ...project, gateId: 'strict' })
    renderProjectRoute('/code-quality/projects/synapse')

    const gate = await screen.findByRole('combobox', { name: 'Quality gate' })
    fireEvent.change(gate, { target: { value: 'strict' } })
    await waitFor(() => expect(api.assignProjectGate).toHaveBeenCalledWith('synapse', 'strict'))
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
  })

  it('preserves coverage upload when starting an analysis from the shell', async () => {
    vi.mocked(api.startProjectAnalysis).mockResolvedValue(buildJob('analysis-running', 'running'))
    renderProjectRoute('/code-quality/projects/synapse')

    const file = new File(['TN:\n'], 'coverage.lcov', { type: 'text/plain' })
    fireEvent.change(await screen.findByLabelText('Coverage report (optional)'), { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: 'Run analysis' }))
    await waitFor(() => expect(api.startProjectAnalysis).toHaveBeenCalledWith('synapse', file))
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
  })

  it('scopes Analysis and Activity requests to their routes', async () => {
    renderProjectRoute('/code-quality/projects/synapse/analysis')
    expect(await screen.findByText('No completed analysis yet')).toBeInTheDocument()
    expect(api.latestProjectAnalysis).toHaveBeenCalledWith('synapse')
    expect(api.projectOverview).not.toHaveBeenCalled()
    expect(api.projectAnalyses).not.toHaveBeenCalled()

    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.projectAnalyses).mockResolvedValue({ items: [], next: null })
    vi.mocked(api.listQualityGates).mockResolvedValue([])
    renderProjectRoute('/code-quality/projects/synapse/activity')
    expect(await screen.findByText('No analysis history yet')).toBeInTheDocument()
    expect(api.projectAnalyses).toHaveBeenCalledWith('synapse')
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
    expect(api.projectOverview).not.toHaveBeenCalled()
  })
})

describe('Project Overview drill-down routes', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview())
    vi.mocked(api.latestProjectAnalysis).mockResolvedValue(buildLatestProjectAnalysis())
    vi.mocked(api.projectAnalyses).mockResolvedValue({ items: [], next: null })
    vi.mocked(api.listQualityGates).mockResolvedValue([])
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
    Object.defineProperty(window, 'matchMedia', { configurable: true, value: vi.fn().mockReturnValue({ matches: false }) })
  })

  it('loads the full analysis only after a detail link is activated', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse?lens=overall')
    const link = await screen.findByRole('link', { name: 'View Security details' })

    fireEvent.mouseOver(link)
    fireEvent.focus(link)
    expect(api.latestProjectAnalysis).not.toHaveBeenCalled()
    expect(api.projectAnalyses).not.toHaveBeenCalled()

    fireEvent.click(link)
    expect(router.state.location.pathname).toBe('/code-quality/projects/synapse/analysis')
    expect(router.state.location.search).toBe('?focus=security&lens=overall')
    expect(await screen.findByRole('heading', { name: 'Analysis findings' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Security dimension'))
    expect(screen.getByRole('button', { name: /SAST security finding/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Reliability finding/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Maintainability finding/i })).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Analysis findings' })).toHaveFocus())
    expect(api.latestProjectAnalysis).toHaveBeenCalledTimes(1)
    expect(api.latestProjectAnalysis).toHaveBeenCalledWith('synapse')
    expect(api.projectAnalyses).not.toHaveBeenCalled()
  })

  it('changes focus and browser history without refetching the loaded analysis', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse/analysis?focus=security&lens=overall')
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Security dimension'))

    await act(async () => {
      await router.navigate('/code-quality/projects/synapse/analysis?focus=reliability&lens=overall')
    })
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Reliability dimension'))
    expect(screen.getByRole('button', { name: /Reliability finding/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /SAST security finding/i })).not.toBeInTheDocument()
    expect(api.latestProjectAnalysis).toHaveBeenCalledTimes(1)

    await act(async () => { await router.navigate(-1) })
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Security dimension'))
    await act(async () => { await router.navigate(1) })
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Reliability dimension'))
    expect(api.latestProjectAnalysis).toHaveBeenCalledTimes(1)
  })

  it('hands New Code ratings to the summary and preserves the lens on Back to Overview', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse?lens=new-code')
    fireEvent.click(await screen.findByRole('link', { name: 'View Security details' }))

    expect(await screen.findByText('Individual New Code issues are not available in this view.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'New Code period' })).toHaveFocus())
    expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('All kinds')
    expect(screen.queryByText('New Code findings')).not.toBeInTheDocument()
    expect(router.state.location.search).toBe('?focus=security&lens=new-code')

    const back = screen.getByRole('link', { name: 'Back to Overview' })
    expect(back).toHaveAttribute('href', '/code-quality/projects/synapse?lens=new-code')
    fireEvent.click(back)
    expect(router.state.location.pathname).toBe('/code-quality/projects/synapse')
    expect(router.state.location.search).toBe('?lens=new-code')
    expect(await screen.findByRole('button', { name: 'New Code' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('normalizes invalid Analysis query values with replace and no extra fetch', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse/analysis?focus=issues&lens=bad&trace=keep')
    expect(await screen.findByRole('heading', { name: 'Analysis findings' })).toBeInTheDocument()
    await waitFor(() => expect(router.state.location.search).toBe('?lens=overall&trace=keep'))
    expect(api.latestProjectAnalysis).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('All kinds')
  })

  it('hands Coverage and Duplications to their existing sections without refetching', async () => {
    const router = renderProjectRoute('/code-quality/projects/synapse/analysis?focus=coverage&lens=overall')
    const coverageHeading = await screen.findByRole('heading', { name: 'Coverage' })
    await waitFor(() => expect(coverageHeading).toHaveFocus())
    expect(screen.getByText('Covered lines')).toBeInTheDocument()
    expect(screen.getByText('Uncovered lines')).toBeInTheDocument()

    await act(async () => {
      await router.navigate('/code-quality/projects/synapse/analysis?focus=duplications&lens=overall')
    })
    const duplicationHeading = screen.getByRole('heading', { name: 'Duplicated blocks' })
    await waitFor(() => expect(duplicationHeading).toHaveFocus())
    expect(screen.getByText('src/a.ts')).toBeInTheDocument()
    expect(screen.getByText('lines 10–20')).toBeInTheDocument()
    expect(api.latestProjectAnalysis).toHaveBeenCalledTimes(1)
  })

  it('keeps Analysis load and no-analysis states primary over focus notices', async () => {
    vi.mocked(api.latestProjectAnalysis).mockRejectedValueOnce(new Error('analysis detail offline'))
    renderProjectRoute('/code-quality/projects/synapse/analysis?focus=coverage&lens=overall')
    expect(await screen.findByText('analysis detail offline')).toBeInTheDocument()
    expect(screen.queryByText('The requested detail is unavailable for this analysis.')).not.toBeInTheDocument()

    vi.resetAllMocks()
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.latestProjectAnalysis).mockResolvedValue(null)
    vi.mocked(api.listQualityGates).mockResolvedValue([])
    renderProjectRoute('/code-quality/projects/synapse/analysis?focus=coverage&lens=overall')
    expect(await screen.findByText('No completed analysis yet')).toBeInTheDocument()
    expect(screen.queryByText('The requested detail is unavailable for this analysis.')).not.toBeInTheDocument()
  })

  it('prevents a stale Project response from focusing or filtering the active Project', async () => {
    const alphaLatest = deferred<ReturnType<typeof buildLatestProjectAnalysis>>()
    const betaLatest = buildLatestProjectAnalysis({
      id: 'beta-analysis',
      sourceRef: 'beta',
      findings: [buildFinding('beta-reliability', 'Beta reliability finding', 'reliability', 'medium')],
    })
    vi.mocked(api.getProject).mockImplementation((key) => Promise.resolve(buildProject(key, key === 'alpha' ? 'Alpha' : 'Beta')))
    vi.mocked(api.latestProjectAnalysis).mockImplementation((key) => key === 'alpha' ? alphaLatest.promise : Promise.resolve(betaLatest))
    const router = renderProjectRoute('/code-quality/projects/alpha/analysis?focus=security&lens=overall')
    await waitFor(() => expect(api.latestProjectAnalysis).toHaveBeenCalledWith('alpha'))

    await act(async () => {
      await router.navigate('/code-quality/projects/beta/analysis?focus=reliability&lens=overall')
    })
    expect(await screen.findByRole('heading', { name: 'Beta' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Reliability dimension'))
    expect(screen.getByRole('button', { name: /Beta reliability finding/i })).toBeInTheDocument()

    alphaLatest.resolve(buildLatestProjectAnalysis({
      id: 'alpha-analysis',
      sourceRef: 'alpha',
      findings: [buildFinding('alpha-sast', 'Alpha stale SAST finding', 'sast', 'high')],
    }))
    await settle()
    expect(screen.queryByRole('button', { name: /Alpha stale SAST finding/i })).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Filter findings by kind' })).toHaveTextContent('Reliability dimension')
    expect(screen.getByRole('heading', { name: 'Analysis findings' })).toHaveFocus()
  })
})

describe('project analysis polling lifecycle', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.getProject).mockImplementation((key) => Promise.resolve(buildProject(key, key === 'alpha' ? 'Alpha' : 'Beta')))
    vi.mocked(api.projectOverview).mockResolvedValue(buildAnalyzedOverview())
    vi.mocked(api.listQualityGates).mockResolvedValue([])
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('ignores a Project A polling response after navigation to Project B', async () => {
    const stale = deferred<ScanJob | null>()
    let alphaCalls = 0
    vi.mocked(api.projectAnalysisStatus).mockImplementation((key) => {
      if (key === 'alpha') {
        alphaCalls += 1
        return alphaCalls === 1 ? Promise.resolve(null) : stale.promise
      }
      return Promise.resolve(null)
    })
    vi.mocked(api.startProjectAnalysis).mockResolvedValue(buildJob('alpha-running', 'running'))
    const router = renderProjectRoute('/code-quality/projects/alpha')
    expect(await screen.findByRole('heading', { name: 'Alpha' })).toBeInTheDocument()

    vi.useFakeTimers()
    await startAnalysisPoll()
    await act(async () => vi.advanceTimersByTimeAsync(1500))
    expect(alphaCalls).toBe(2)

    await act(async () => {
      await router.navigate('/code-quality/projects/beta')
      await Promise.resolve()
    })
    expect(screen.getByRole('heading', { name: 'Beta' })).toBeInTheDocument()
    stale.resolve(buildJob('alpha-stale', 'running'))
    await settle()

    expect(screen.getByText('Ready')).toBeInTheDocument()
    expect(screen.queryByText('Analyzing')).not.toBeInTheDocument()
  })

  it('does not let a stale terminal response stop the active Project B poll', async () => {
    const staleTerminal = deferred<ScanJob | null>()
    const betaThirdRequest = deferred<ScanJob | null>()
    let alphaCalls = 0
    let betaCalls = 0
    vi.mocked(api.projectAnalysisStatus).mockImplementation((key) => {
      if (key === 'alpha') {
        alphaCalls += 1
        return alphaCalls === 1 ? Promise.resolve(null) : staleTerminal.promise
      }
      betaCalls += 1
      if (betaCalls <= 2) return Promise.resolve(buildJob('beta-running', 'running'))
      return betaThirdRequest.promise
    })
    vi.mocked(api.startProjectAnalysis).mockResolvedValue(buildJob('alpha-running', 'running'))
    const router = renderProjectRoute('/code-quality/projects/alpha')
    expect(await screen.findByRole('heading', { name: 'Alpha' })).toBeInTheDocument()

    vi.useFakeTimers()
    await startAnalysisPoll()
    await act(async () => vi.advanceTimersByTimeAsync(1500))
    await act(async () => {
      await router.navigate('/code-quality/projects/beta')
      await Promise.resolve()
    })
    await act(async () => vi.advanceTimersByTimeAsync(1500))
    expect(betaCalls).toBe(2)

    const betaOverviewCalls = vi.mocked(api.projectOverview).mock.calls.filter(([key]) => key === 'beta').length
    staleTerminal.resolve(buildJob('alpha-succeeded', 'succeeded'))
    await settle()
    expect(vi.mocked(api.projectOverview).mock.calls.filter(([key]) => key === 'beta')).toHaveLength(betaOverviewCalls)

    await act(async () => vi.advanceTimersByTimeAsync(1500))
    expect(betaCalls).toBe(3)
  })

  it('does not overlap slow analysis-status requests', async () => {
    const slow = deferred<ScanJob | null>()
    const next = deferred<ScanJob | null>()
    let calls = 0
    vi.mocked(api.projectAnalysisStatus).mockImplementation(() => {
      calls += 1
      if (calls === 1) return Promise.resolve(null)
      if (calls === 2) return slow.promise
      return next.promise
    })
    vi.mocked(api.startProjectAnalysis).mockResolvedValue(buildJob('alpha-running', 'running'))
    renderProjectRoute('/code-quality/projects/alpha')
    expect(await screen.findByRole('heading', { name: 'Alpha' })).toBeInTheDocument()

    vi.useFakeTimers()
    await startAnalysisPoll()
    await act(async () => vi.advanceTimersByTimeAsync(1500))
    await act(async () => vi.advanceTimersByTimeAsync(10_000))
    expect(calls).toBe(2)

    slow.resolve(buildJob('alpha-running', 'running'))
    await settle()
    await act(async () => vi.advanceTimersByTimeAsync(1499))
    expect(calls).toBe(2)
    await act(async () => vi.advanceTimersByTimeAsync(1))
    expect(calls).toBe(3)
  })

  it('refreshes the active Overview exactly once after a succeeded job', async () => {
    let calls = 0
    vi.mocked(api.projectAnalysisStatus).mockImplementation(() => {
      calls += 1
      return Promise.resolve(calls === 1 ? null : buildJob('alpha-succeeded', 'succeeded'))
    })
    vi.mocked(api.startProjectAnalysis).mockResolvedValue(buildJob('alpha-running', 'running'))
    renderProjectRoute('/code-quality/projects/alpha')
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()

    vi.useFakeTimers()
    await startAnalysisPoll()
    await act(async () => vi.advanceTimersByTimeAsync(1500))
    await settle()
    expect(api.projectOverview).toHaveBeenCalledTimes(2)

    await act(async () => vi.advanceTimersByTimeAsync(10_000))
    expect(api.projectOverview).toHaveBeenCalledTimes(2)
    expect(calls).toBe(2)
  })

  it('does not refresh Overview after a failed job', async () => {
    let calls = 0
    vi.mocked(api.projectAnalysisStatus).mockImplementation(() => {
      calls += 1
      return Promise.resolve(calls === 1 ? null : buildJob('alpha-failed', 'failed', 'analysis failed'))
    })
    vi.mocked(api.startProjectAnalysis).mockResolvedValue(buildJob('alpha-running', 'running'))
    renderProjectRoute('/code-quality/projects/alpha')
    expect(await screen.findByText('Quality Gate Failed')).toBeInTheDocument()

    vi.useFakeTimers()
    await startAnalysisPoll()
    await act(async () => vi.advanceTimersByTimeAsync(1500))
    await settle()

    expect(screen.getByText('analysis failed')).toBeInTheDocument()
    expect(api.projectOverview).toHaveBeenCalledTimes(1)
  })
})

describe('project Activity pagination lifecycle', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('ignores an older Project A page after navigation to Project B', async () => {
    const staleOlder = deferred<Awaited<ReturnType<typeof api.projectAnalyses>>>()
    vi.mocked(api.projectAnalyses).mockImplementation((key, cursor) => {
      if (key === 'alpha' && cursor) return staleOlder.promise
      if (key === 'alpha') return Promise.resolve(activityPage('alpha-latest', 'ref-alpha-latest', alphaCursor))
      return Promise.resolve(activityPage('beta-latest', 'ref-beta-latest'))
    })
    const router = renderActivityLifecycleRoute('/projects/alpha/activity')
    expect(await screen.findByText('ref-alpha-latest')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load older analyses' }))

    await act(async () => {
      await router.navigate('/projects/beta/activity')
    })
    expect(await screen.findByText('ref-beta-latest')).toBeInTheDocument()
    staleOlder.resolve(activityPage('alpha-older', 'ref-alpha-stale'))
    await settle()

    expect(screen.queryByText('ref-alpha-stale')).not.toBeInTheDocument()
    expect(screen.getByText('ref-beta-latest')).toBeInTheDocument()
  })

  it('ignores an older page from a previous analysis revision', async () => {
    const staleOlder = deferred<Awaited<ReturnType<typeof api.projectAnalyses>>>()
    let firstPageCalls = 0
    vi.mocked(api.projectAnalyses).mockImplementation((_key, cursor) => {
      if (cursor) return staleOlder.promise
      firstPageCalls += 1
      return Promise.resolve(firstPageCalls === 1
        ? activityPage('latest-1', 'ref-before-refresh', alphaCursor)
        : activityPage('latest-2', 'ref-after-refresh'))
    })
    renderActivityLifecycleRoute('/projects/alpha/activity')
    expect(await screen.findByText('ref-before-refresh')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load older analyses' }))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh activity revision' }))
    expect(await screen.findByText('ref-after-refresh')).toBeInTheDocument()

    staleOlder.resolve(activityPage('older-stale', 'ref-older-stale'))
    await settle()
    expect(screen.queryByText('ref-older-stale')).not.toBeInTheDocument()
  })

  it('keeps current rows visible when loading an older page fails', async () => {
    vi.mocked(api.projectAnalyses).mockImplementation((_key, cursor) => cursor
      ? Promise.reject(new Error('older page offline'))
      : Promise.resolve(activityPage('latest', 'ref-current', alphaCursor)))
    renderActivityLifecycleRoute('/projects/alpha/activity')
    expect(await screen.findByText('ref-current')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load older analyses' }))

    expect(await screen.findByText('older page offline')).toBeInTheDocument()
    expect(screen.getByText('ref-current')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Load older analyses' })).toBeEnabled()
  })

  it('retries a failed older page and appends the successful result', async () => {
    let olderCalls = 0
    vi.mocked(api.projectAnalyses).mockImplementation((_key, cursor) => {
      if (!cursor) return Promise.resolve(activityPage('latest', 'ref-current', alphaCursor))
      olderCalls += 1
      return olderCalls === 1
        ? Promise.reject(new Error('older page offline'))
        : Promise.resolve(activityPage('older', 'ref-older'))
    })
    renderActivityLifecycleRoute('/projects/alpha/activity')
    expect(await screen.findByText('ref-current')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Load older analyses' }))
    expect(await screen.findByText('older page offline')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Load older analyses' }))
    expect(await screen.findByText('ref-older')).toBeInTheDocument()
    expect(screen.queryByText('older page offline')).not.toBeInTheDocument()
    expect(olderCalls).toBe(2)
  })

  it('coalesces duplicate load-older clicks into one request', async () => {
    const older = deferred<Awaited<ReturnType<typeof api.projectAnalyses>>>()
    vi.mocked(api.projectAnalyses).mockImplementation((_key, cursor) => cursor
      ? older.promise
      : Promise.resolve(activityPage('latest', 'ref-current', alphaCursor)))
    renderActivityLifecycleRoute('/projects/alpha/activity')
    expect(await screen.findByText('ref-current')).toBeInTheDocument()
    const button = screen.getByRole('button', { name: 'Load older analyses' })
    fireEvent.click(button)
    fireEvent.click(button)

    expect(api.projectAnalyses).toHaveBeenCalledTimes(2)
  })
})

function renderProjectRoute(initialPath: string) {
  const router = createMemoryRouter([
    {
      path: '/code-quality/projects/:key',
      element: <CodeQualityProject />,
      children: [
        { index: true, element: <ProjectOverviewPage /> },
        { path: 'analysis', element: <ProjectAnalysisPage /> },
        { path: 'activity', element: <ProjectActivityPage /> },
      ],
    },
  ], { initialEntries: [initialPath] })
  render(<RouterProvider router={router} />)
  return router
}

const alphaCursor = { beforeCreatedAt: '2026-07-17T00:00:00Z', beforeId: 'alpha-cursor' }

function activityPage(id: string, sourceRef: string, next: typeof alphaCursor | null = null) {
  return { items: [buildAnalysis(id, sourceRef)], next }
}

function ActivityLifecycleShell() {
  const { key = '' } = useParams()
  const [analysisRevision, setAnalysisRevision] = useState(0)
  return (
    <>
      <button type="button" onClick={() => setAnalysisRevision((value) => value + 1)}>Refresh activity revision</button>
      <Outlet context={{ projectKey: key, analysisRevision }} />
    </>
  )
}

function renderActivityLifecycleRoute(initialPath: string) {
  const router = createMemoryRouter([
    {
      path: '/projects/:key/activity',
      element: <ActivityLifecycleShell />,
      children: [{ index: true, element: <ProjectActivityPage /> }],
    },
  ], { initialEntries: [initialPath] })
  render(<RouterProvider router={router} />)
  return router
}

async function startAnalysisPoll() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Run analysis' }))
    await Promise.resolve()
  })
}

async function settle() {
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
  })
}
