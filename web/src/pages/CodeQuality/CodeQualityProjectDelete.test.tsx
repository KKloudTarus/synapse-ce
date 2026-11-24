import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CodeQualityProject } from './CodeQualityProject'

// vi.mock is hoisted above the module body, so the shared doubles come from vi.hoisted.
const { navigate, api } = vi.hoisted(() => ({
  navigate: vi.fn(),
  api: {
    getProject: vi.fn(),
    projectAnalysisStatus: vi.fn(),
    projectBranches: vi.fn(),
    listQualityGates: vi.fn(),
    deleteProject: vi.fn(),
  },
}))
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})
vi.mock('../../lib/api', () => ({ api, ApiError: class ApiError extends Error {} }))

const project = {
  id: 'p1',
  key: 'demo',
  name: 'Demo',
  sourceBinding: { kind: 'git', value: 'https://host/org/demo.git', ref: 'main' },
  defaultProfileByLang: {},
  latestAnalysis: null,
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/code-quality/projects/demo']}>
      <Routes>
        <Route path="/code-quality/projects/:key" element={<CodeQualityProject />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('project deletion', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getProject.mockResolvedValue(project)
    api.projectAnalysisStatus.mockResolvedValue(null)
    api.projectBranches.mockResolvedValue([])
    api.listQualityGates.mockResolvedValue([])
    api.deleteProject.mockResolvedValue(undefined)
  })

  it('asks for confirmation before deleting and then returns to the list', async () => {
    renderPage()
    const trigger = await screen.findByRole('button', { name: /delete/i })

    await userEvent.click(trigger)
    // The first click must not delete anything: this takes a project's analyses with it.
    expect(api.deleteProject).not.toHaveBeenCalled()
    expect(screen.getByText(/delete demo and its analyses\?/i)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /^delete$/i }))
    await waitFor(() => expect(api.deleteProject).toHaveBeenCalledWith('demo'))
    expect(navigate).toHaveBeenCalledWith('/code-quality', { replace: true })
  })

  it('cancelling leaves the project alone', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /delete/i }))
    await userEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(api.deleteProject).not.toHaveBeenCalled()
    expect(screen.queryByText(/and its analyses\?/i)).not.toBeInTheDocument()
  })

  it('surfaces a refused delete instead of navigating away', async () => {
    api.deleteProject.mockRejectedValue(new Error('project has running analyses'))
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /delete/i }))
    await userEvent.click(screen.getByRole('button', { name: /^delete$/i }))
    expect(await screen.findByText(/project has running analyses/i)).toBeInTheDocument()
    expect(navigate).not.toHaveBeenCalled()
  })
})

// A project whose analyses sealed evidence is permanent, because the custody chain is append-only.
// The control used to offer Delete anyway, and the operator met a 409 after clicking; worse, with
// the refusal misclassified it read as a retryable internal error with a Retry that could never
// work. The reason now reaches the control itself.
describe('project deletion blocked by sealed evidence', () => {
  const reason = "This project's analyses sealed evidence, and the custody chain is append-only, so it cannot be deleted."

  beforeEach(() => {
    vi.resetAllMocks()
    api.projectAnalysisStatus.mockResolvedValue(null)
    api.projectBranches.mockResolvedValue([])
    api.listQualityGates.mockResolvedValue([])
  })

  it('disables Delete and says why, without asking the server', async () => {
    api.getProject.mockResolvedValue({ ...project, deletionBlocked: reason })
    renderPage()
    const button = await screen.findByRole('button', { name: /delete/i })
    expect(button).toBeDisabled()
    // title is unreliable on a disabled control, so the reason is also the accessible name.
    expect(button).toHaveAccessibleName(new RegExp('sealed evidence'))
    expect(api.deleteProject).not.toHaveBeenCalled()
  })

  it('leaves Delete alone when nothing blocks it', async () => {
    api.getProject.mockResolvedValue({ ...project, deletionBlocked: '' })
    renderPage()
    expect(await screen.findByRole('button', { name: /delete/i })).toBeEnabled()
  })

  it('leaves Delete alone when an older server sends no signal', async () => {
    api.getProject.mockResolvedValue(project)
    renderPage()
    expect(await screen.findByRole('button', { name: /delete/i })).toBeEnabled()
  })
})
