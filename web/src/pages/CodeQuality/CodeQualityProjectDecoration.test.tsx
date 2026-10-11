import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CodeQualityProject } from './CodeQualityProject'

// vi.mock is hoisted above the module body, so the shared doubles come from vi.hoisted.
const { api } = vi.hoisted(() => ({
  api: {
    getProject: vi.fn(),
    projectAnalysisStatus: vi.fn(),
    projectBranches: vi.fn(),
    listQualityGates: vi.fn(),
    me: vi.fn(),
    setProjectDecoration: vi.fn(),
  },
}))
vi.mock('../../lib/api', () => ({ api, ApiError: class ApiError extends Error {} }))

const project = {
  id: 'p1',
  key: 'demo',
  name: 'Demo',
  sourceBinding: { kind: 'git', value: 'https://host/org/demo.git', ref: 'main' },
  defaultProfileByLang: {},
  gateId: '',
  decoratePullRequests: false,
  createdAt: null,
  latestAnalysis: null,
  latestJob: null,
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

async function decorationSwitch() {
  return screen.findByRole('switch', { name: 'PR decoration' })
}

describe('project PR decoration toggle', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getProject.mockResolvedValue(project)
    api.projectAnalysisStatus.mockResolvedValue(null)
    api.projectBranches.mockResolvedValue([])
    api.listQualityGates.mockResolvedValue([])
    api.me.mockResolvedValue({ id: 'u1', name: 'Operator', role: 'consultant' })
  })

  it('reflects the stored state', async () => {
    api.getProject.mockResolvedValue({ ...project, decoratePullRequests: true })
    renderPage()
    const toggle = await decorationSwitch()
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(toggle).toBeChecked()
  })

  it('turns decoration on and shows the server state', async () => {
    api.setProjectDecoration.mockResolvedValue({ ...project, decoratePullRequests: true })
    renderPage()
    const toggle = await decorationSwitch()
    expect(toggle).not.toBeChecked()
    await waitFor(() => expect(toggle).toBeEnabled())

    await userEvent.click(toggle)
    await waitFor(() => expect(api.setProjectDecoration).toHaveBeenCalledWith('demo', true))
    await waitFor(() => expect(toggle).toBeChecked())
  })

  it('turns decoration off', async () => {
    api.getProject.mockResolvedValue({ ...project, decoratePullRequests: true })
    api.setProjectDecoration.mockResolvedValue({ ...project, decoratePullRequests: false })
    renderPage()
    const toggle = await decorationSwitch()
    await waitFor(() => expect(toggle).toBeEnabled())

    await userEvent.click(toggle)
    await waitFor(() => expect(api.setProjectDecoration).toHaveBeenCalledWith('demo', false))
    await waitFor(() => expect(toggle).not.toBeChecked())
  })

  it('surfaces a refused change and keeps the stored state', async () => {
    api.setProjectDecoration.mockRejectedValue(new Error('forbidden'))
    renderPage()
    const toggle = await decorationSwitch()
    await waitFor(() => expect(toggle).toBeEnabled())

    await userEvent.click(toggle)
    expect(await screen.findByText('forbidden')).toBeInTheDocument()
    expect(toggle).not.toBeChecked()
    expect(toggle).toBeEnabled()
  })

  it.each(['reviewer', 'readonly'])('is disabled for a %s, who lacks the operate permission', async (role) => {
    api.me.mockResolvedValue({ id: 'u2', name: 'Someone', role })
    renderPage()
    const toggle = await decorationSwitch()
    await waitFor(() => expect(api.me).toHaveBeenCalled())
    expect(toggle).toBeDisabled()
    await userEvent.click(toggle)
    expect(api.setProjectDecoration).not.toHaveBeenCalled()
  })

  it('stays disabled when the current user cannot be resolved', async () => {
    api.me.mockRejectedValue(new Error('unauthorized'))
    renderPage()
    const toggle = await decorationSwitch()
    await waitFor(() => expect(api.me).toHaveBeenCalled())
    expect(toggle).toBeDisabled()
  })
})
