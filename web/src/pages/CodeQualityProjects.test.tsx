import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { api } from '../lib/api'
import { CodeQualityProject } from './CodeQualityProject'
import { CodeQualityProjects } from './CodeQualityProjects'

vi.mock('../lib/api', () => ({ api: { listProjects: vi.fn(), createProject: vi.fn(), createProjectFromArchive: vi.fn(), getProject: vi.fn(), startProjectAnalysis: vi.fn(), projectAnalysisStatus: vi.fn(), latestProjectAnalysis: vi.fn() } }))

const project = { id: 'p1', name: 'Synapse', key: 'synapse', sourceBinding: { kind: 'git' as const, value: 'https://example.com/repo.git', ref: 'main' }, defaultProfileByLang: {}, gateId: '', createdAt: null }

function renderList() { return render(<MemoryRouter><CodeQualityProjects /></MemoryRouter>) }

describe('Code Quality projects', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue(null)
    vi.mocked(api.latestProjectAnalysis).mockResolvedValue(null)
  })

  it('renders loading, empty, and list states', async () => {
    vi.mocked(api.listProjects).mockReturnValue(new Promise(() => {}))
    const view = renderList()
    expect(screen.getByText('Loading projects…')).toBeInTheDocument()
    view.unmount()

    vi.mocked(api.listProjects).mockResolvedValue([])
    renderList()
    expect(await screen.findByText('No code quality projects yet')).toBeInTheDocument()
  })

  it('retries a failed project list', async () => {
    vi.mocked(api.listProjects).mockRejectedValueOnce(new Error('Network error')).mockResolvedValue([])
    renderList()
    expect(await screen.findByText('Network error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No code quality projects yet')).toBeInTheDocument()
  })

  it('renders the latest project analysis status', async () => {
    vi.mocked(api.listProjects).mockResolvedValue([project])
    vi.mocked(api.projectAnalysisStatus).mockResolvedValue({ id: 'j1', engagementId: '', target: project.sourceBinding.value, kind: 'git', status: 'succeeded', stage: 'done', progress: 100, error: '', startedAt: null, finishedAt: null, debugEvents: [] })
    renderList()
    expect(await screen.findByRole('heading', { name: 'Synapse' })).toBeInTheDocument()
    expect(await screen.findByText('Analyzed')).toBeInTheDocument()
    expect(screen.getByText('Open project')).toBeInTheDocument()
  })

  it('creates and navigates to the shell', async () => {
    vi.mocked(api.listProjects).mockResolvedValue([])
    vi.mocked(api.createProject).mockResolvedValue(project)
    vi.mocked(api.startProjectAnalysis).mockResolvedValue({ id: 'j1', engagementId: 'e1', target: project.sourceBinding.value, kind: 'git', status: 'running', stage: 'queued', progress: 0, error: '', startedAt: null, finishedAt: null, debugEvents: [] })
    render(
      <MemoryRouter initialEntries={['/code-quality']}>
        <Routes><Route path="/code-quality" element={<CodeQualityProjects />} /><Route path="/code-quality/projects/:key" element={<div>Project shell route</div>} /></Routes>
      </MemoryRouter>,
    )
    fireEvent.click(await screen.findByRole('button', { name: /New project/i }))
    const sourceKind = screen.getByRole('combobox', { name: 'Source kind' })
    expect(sourceKind).toHaveAttribute('id', 'project-source-kind')
    expect(document.querySelector('label[for="project-source-kind"]')).toHaveTextContent('Source kind')
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Synapse' } })
    fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'https://example.com/repo.git' } })
    fireEvent.click(screen.getByRole('button', { name: /Create project/i }))
    await waitFor(() => expect(api.createProject).toHaveBeenCalledWith(expect.objectContaining({ key: 'synapse' })))
    expect(api.startProjectAnalysis).toHaveBeenCalledWith('synapse')
    expect(await screen.findByText('Project shell route')).toBeInTheDocument()
  })

  it('navigates to the created project when auto-start fails', async () => {
    vi.mocked(api.listProjects).mockResolvedValue([])
    vi.mocked(api.createProject).mockResolvedValue(project)
    vi.mocked(api.getProject).mockResolvedValue(project)
    vi.mocked(api.startProjectAnalysis).mockRejectedValue(new Error('Scanner unavailable'))
    render(
      <MemoryRouter initialEntries={['/code-quality']}>
        <Routes>
          <Route path="/code-quality" element={<CodeQualityProjects />} />
          <Route path="/code-quality/projects/:key" element={<CodeQualityProject />} />
        </Routes>
      </MemoryRouter>,
    )
    fireEvent.click(await screen.findByRole('button', { name: /New project/i }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Synapse' } })
    fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'https://example.com/repo.git' } })
    fireEvent.click(screen.getByRole('button', { name: /Create project/i }))
    expect(await screen.findByRole('heading', { name: 'Synapse' })).toBeInTheDocument()
    expect(screen.getByText('Scanner unavailable')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Run analysis/i })).toBeInTheDocument()
  })


  it('renders an honest project shell empty state', async () => {
    vi.mocked(api.getProject).mockResolvedValue(project)
    render(<MemoryRouter initialEntries={['/code-quality/projects/synapse']}><Routes><Route path="/code-quality/projects/:key" element={<CodeQualityProject />} /></Routes></MemoryRouter>)
    expect(await screen.findByRole('heading', { name: 'Synapse' })).toBeInTheDocument()
    expect(screen.getByText('No analyses yet')).toBeInTheDocument()
  })
})
