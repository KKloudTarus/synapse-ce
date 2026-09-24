import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../../lib/api'
import type { IssueReviewEvent, ProjectIssue } from '../../../lib/types'
import { IssueDetail } from './IssueDetail'

vi.mock('../../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../../lib/api')>('../../../lib/api')
  return {
    ...actual,
    api: { transitionProjectIssue: vi.fn(), getProjectIssueHistory: vi.fn() },
  }
})

const issue: ProjectIssue = {
  id: 'issue-1',
  ruleKey: 'go:S1234',
  ruleName: 'Unsafe exec',
  type: 'vulnerability',
  title: 'Command built from user input',
  description: 'The argument reaches exec.Command without validation.',
  severity: 'high',
  findingKind: 'sast',
  cwe: 'CWE-78',
  language: 'go',
  file: 'internal/run.go',
  location: 'internal/run.go:42',
  status: 'open',
  version: 3,
  isNew: false,
  firstSeenAnalysisId: 'analysis-1',
  lastSeenAnalysisId: 'analysis-4',
  firstSeenAt: '2026-09-01T07:00:00Z',
  lastSeenAt: '2026-09-10T07:00:00Z',
}

const events: IssueReviewEvent[] = [
  { from: 'open', to: 'accepted', actor: 'reviewer@example.test', rationale: 'Mitigated by the gateway allowlist.', version: 2, createdAt: '2026-09-05T07:00:00Z' },
]

function renderDetail() {
  return render(
    <MemoryRouter>
      <IssueDetail projectKey="payments" issue={issue} onClose={() => {}} onTransitioned={() => {}} />
    </MemoryRouter>,
  )
}

describe('IssueDetail review history', () => {
  beforeEach(() => vi.resetAllMocks())

  it('shows who changed the status and the rationale they recorded', async () => {
    vi.mocked(api.getProjectIssueHistory).mockResolvedValue(events)
    renderDetail()

    expect(await screen.findByText('Mitigated by the gateway allowlist.')).toBeInTheDocument()
    expect(screen.getByText('by reviewer@example.test')).toBeInTheDocument()
  })

  it('says no decision was recorded rather than leaving the section blank', async () => {
    vi.mocked(api.getProjectIssueHistory).mockResolvedValue([])
    renderDetail()

    expect(await screen.findByText('No review decisions recorded yet.')).toBeInTheDocument()
  })

  // An unreachable history service must not read as an issue nobody has reviewed.
  it('surfaces a history failure instead of rendering an empty history', async () => {
    vi.mocked(api.getProjectIssueHistory).mockRejectedValue(new Error('history unavailable'))
    renderDetail()

    expect(await screen.findByText(/history unavailable/)).toBeInTheDocument()
    expect(screen.queryByText('No review decisions recorded yet.')).not.toBeInTheDocument()
  })

  it('reloads the history after a committed transition', async () => {
    vi.mocked(api.getProjectIssueHistory).mockResolvedValue([])
    vi.mocked(api.transitionProjectIssue).mockResolvedValue({ ...issue, status: 'accepted', version: 4 })
    renderDetail()

    await screen.findByText('No review decisions recorded yet.')
    await waitFor(() => expect(api.getProjectIssueHistory).toHaveBeenCalledTimes(1))

    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: 'Accepted for this release.' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply Classification' }))

    await waitFor(() => expect(api.getProjectIssueHistory).toHaveBeenCalledTimes(2))
  })
})
