import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { StrictMode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type ProjectSourceFinding, type ProjectSourceFindingPage } from '../../lib/api'
import { ProjectSourceFindings } from './ProjectSourceFindings'

let projectKey = 'payments'

vi.mock('../../lib/api', () => ({ api: { listProjectSourceFindings: vi.fn(), getProjectSourceFinding: vi.fn(), updateProjectSourceFindingStatus: vi.fn(), me: vi.fn() } }))
vi.mock('./CodeQualityProject', () => ({ useProjectRouteContext: () => ({ projectKey }) }))
vi.mock('../EngagementDetail/components/TicketsPanel', () => ({ TicketsPanel: (props: { projectKey: string; findingId: string }) => <p data-testid="ticket-scope">{props.projectKey}:{props.findingId}</p> }))

const finding = (id: string, overrides: Partial<ProjectSourceFinding> = {}): ProjectSourceFinding => ({
  id,
  title: `Finding ${id}`,
  description: 'Scanner result',
  severity: 'high' as const,
  cvssVector: '',
  dedupKey: '',
  kev: false,
  riskScore: 0,
  class: 'third_party',
  scope: 'unknown',
  reachability: 'unknown',
  impact: '',
  priority: 3,
  assignee: '',
  status: 'open',
  cwe: 'CWE-79',
  fixedVersion: '2.17.1',
  sources: ['osv'],
  version: 2,
  kind: 'sca',
  evidenceScore: 0,
  proposedBy: '',
  complianceControls: [],
  ...overrides,
})

const sourceFindingPage = (items: ProjectSourceFinding[], nextCursor = ''): ProjectSourceFindingPage => ({ items, nextCursor })

describe('ProjectSourceFindings', () => {
  beforeEach(() => {
    projectKey = 'payments'
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ role: 'reviewer' } as never)
    vi.mocked(api.listProjectSourceFindings).mockResolvedValue(sourceFindingPage([finding('first'), finding('second')]))
    vi.mocked(api.getProjectSourceFinding).mockImplementation(async (_projectKey, findingID) => finding(findingID))
  })

  it('opens the Project deep-linked finding and passes only Project context to tickets', async () => {
    render(<MemoryRouter initialEntries={['/code-quality/projects/payments/source-findings#finding-second']}><ProjectSourceFindings /></MemoryRouter>)

    expect(await screen.findByRole('button', { name: /Finding second/ })).toBeInTheDocument()
    expect(await screen.findByTestId('ticket-scope')).toHaveTextContent('payments:second')
    expect(screen.getByRole('button', { name: /Finding second/ })).toHaveAttribute('aria-current', 'true')
    expect(api.listProjectSourceFindings).toHaveBeenCalledWith('payments', '')
    expect(api.getProjectSourceFinding).toHaveBeenCalledWith('payments', 'second')
  })

  it('shows a truthful empty state and does not offer an invented analysis result', async () => {
    vi.mocked(api.listProjectSourceFindings).mockResolvedValue(sourceFindingPage([]))
    render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)
    expect(await screen.findByText('No source findings')).toBeInTheDocument()
  })

  it('shows a permission failure without prior findings', async () => {
    vi.mocked(api.listProjectSourceFindings).mockRejectedValue(new Error('You do not have permission to view Project source findings.'))
    render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)
    expect(await screen.findByText('You do not have permission to view Project source findings.')).toBeInTheDocument()
    expect(screen.queryByText('Finding first')).not.toBeInTheDocument()
  })

  it('updates triage through the Project route with its current version', async () => {
    vi.mocked(api.updateProjectSourceFindingStatus).mockResolvedValue(finding('first', { status: 'confirmed', version: 3 }))
    render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)
    const status = await screen.findByLabelText('Triage status')
    fireEvent.change(status, { target: { value: 'confirmed' } })
    await waitFor(() => expect(api.updateProjectSourceFindingStatus).toHaveBeenCalledWith('payments', 'first', 'confirmed', 2))
  })

  it('ignores a late list response after the Project route changes', async () => {
    let resolveOld!: (value: ProjectSourceFindingPage) => void
    vi.mocked(api.listProjectSourceFindings)
      .mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve }) as never)
      .mockResolvedValueOnce(sourceFindingPage([finding('current')]))
    const view = render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)
    projectKey = 'inventory'
    view.rerender(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)
    expect(await screen.findByText('Finding current')).toBeInTheDocument()
    resolveOld(sourceFindingPage([finding('stale')]))
    await waitFor(() => expect(screen.queryByText('Finding stale')).not.toBeInTheDocument())
  })

  it('replaces the bounded list page when moving to the next cursor', async () => {
    vi.mocked(api.listProjectSourceFindings)
      .mockResolvedValueOnce(sourceFindingPage([finding('first')], 'cursor-1'))
      .mockResolvedValueOnce(sourceFindingPage([finding('second')]))

    render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)
    expect(await screen.findByText('Finding first')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    expect(await screen.findByText('Finding second')).toBeInTheDocument()
    expect(api.listProjectSourceFindings).toHaveBeenLastCalledWith('payments', 'cursor-1')
    expect(screen.queryByText('Finding first')).not.toBeInTheDocument()
  })

  it('refreshes both the bounded page and the current deep link', async () => {
    vi.mocked(api.getProjectSourceFinding)
      .mockResolvedValueOnce(finding('second', { status: 'open', version: 2 }))
      .mockResolvedValueOnce(finding('second', { status: 'confirmed', version: 3 }))
    render(<MemoryRouter initialEntries={['/code-quality/projects/payments/source-findings#finding-second']}><ProjectSourceFindings /></MemoryRouter>)

    expect(await screen.findByLabelText('Triage status')).toHaveValue('open')
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))

    await waitFor(() => expect(api.getProjectSourceFinding).toHaveBeenCalledTimes(2))
    expect(screen.getByLabelText('Triage status')).toHaveValue('confirmed')
    expect(api.listProjectSourceFindings).toHaveBeenCalledTimes(2)
  })

  it('ignores a delayed triage success after the user selects another finding', async () => {
    let resolveUpdate!: (value: ProjectSourceFinding) => void
    vi.mocked(api.updateProjectSourceFindingStatus).mockImplementationOnce(() => new Promise((resolve) => { resolveUpdate = resolve }) as never)
    render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)

    const firstStatus = await screen.findByLabelText('Triage status')
    fireEvent.change(firstStatus, { target: { value: 'confirmed' } })
    expect(firstStatus).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /Finding second/ }))
    expect(await screen.findByTestId('ticket-scope')).toHaveTextContent('payments:second')

    await act(async () => { resolveUpdate(finding('first', { status: 'confirmed', version: 3 })) })

    expect(screen.getByLabelText('Triage status')).toHaveValue('open')
    expect(screen.getByLabelText('Triage status')).not.toBeDisabled()
    expect(screen.getByTestId('ticket-scope')).toHaveTextContent('payments:second')
    expect(api.listProjectSourceFindings).toHaveBeenCalledTimes(1)
  })

  it('ignores a delayed triage failure after the user selects another finding', async () => {
    let rejectUpdate!: (reason?: unknown) => void
    vi.mocked(api.updateProjectSourceFindingStatus).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectUpdate = reject }) as never)
    render(<MemoryRouter><ProjectSourceFindings /></MemoryRouter>)

    fireEvent.change(await screen.findByLabelText('Triage status'), { target: { value: 'confirmed' } })
    fireEvent.click(screen.getByRole('button', { name: /Finding second/ }))
    expect(await screen.findByTestId('ticket-scope')).toHaveTextContent('payments:second')

    await act(async () => { rejectUpdate(new Error('first finding failed')) })

    expect(screen.getByLabelText('Triage status')).toHaveValue('open')
    expect(screen.getByLabelText('Triage status')).not.toBeDisabled()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByTestId('ticket-scope')).toHaveTextContent('payments:second')
  })

  it('treats malformed deep-link encodings as an ordinary list route', async () => {
    render(<MemoryRouter initialEntries={['/code-quality/projects/payments/source-findings#finding-%']}><ProjectSourceFindings /></MemoryRouter>)

    expect(await screen.findByRole('button', { name: /Finding first/ })).toBeInTheDocument()
    expect(api.getProjectSourceFinding).not.toHaveBeenCalled()
  })
  it('completes triage after StrictMode effect replay', async () => {
    vi.mocked(api.updateProjectSourceFindingStatus).mockResolvedValue(finding('first', { status: 'confirmed', version: 3 }))
    render(<StrictMode><MemoryRouter><ProjectSourceFindings /></MemoryRouter></StrictMode>)
    const status = await screen.findByLabelText('Triage status')
    fireEvent.change(status, { target: { value: 'confirmed' } })
    await waitFor(() => expect(api.updateProjectSourceFindingStatus).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(screen.getByLabelText('Triage status')).not.toBeDisabled())
    expect(vi.mocked(api.listProjectSourceFindings).mock.calls.length).toBeGreaterThan(2)
  })

  it('does not mark another page row current for an off-page deep link', async () => {
    render(<MemoryRouter initialEntries={['/code-quality/projects/payments/source-findings#finding-offpage']}><ProjectSourceFindings /></MemoryRouter>)
    expect(await screen.findByTestId('ticket-scope')).toHaveTextContent('payments:offpage')
    expect(screen.getByRole('button', { name: /Finding first/ })).not.toHaveAttribute('aria-current')
    expect(screen.getByRole('button', { name: /Finding second/ })).not.toHaveAttribute('aria-current')
  })

})
