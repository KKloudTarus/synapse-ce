import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { ImportedFinding } from '../../lib/types'
import { ImportedFindingsTab } from './ImportedFindingsTab'

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api')
  return {
    ...actual,
    api: { listImportedFindings: vi.fn(), findings: vi.fn(), bindObservation: vi.fn() },
  }
})

function imported(overrides: Partial<ImportedFinding>): ImportedFinding {
  return {
    id: 'obs-1',
    findingId: '',
    binding: 'none',
    approvedFindingId: '',
    bindingVersion: 0,
    severity: 'high',
    title: 'Plaintext transport',
    message: 'http client without TLS',
    path: 'internal/client.go',
    startLine: 17,
    startColumn: 0,
    logicalName: '',
    suppressedByTool: false,
    fingerprint: 'abc',
    external: true,
    canSelfPromote: false,
    tool: 'semgrep',
    toolVersion: '1.2.3',
    rule: 'go.use-tls',
    sourceDigest: 'sha256:doc',
    ingestedBy: 'human:alice',
    ingestedAt: '2026-11-24T10:00:00Z',
    ...overrides,
  }
}

describe('ImportedFindingsTab link column', () => {
  beforeEach(() => vi.resetAllMocks())

  // A deduplicator match on file and line is evidence. Rendering it the same way as a recorded decision
  // is what let a coincidence of line number merge two remediation workflows.
  it('calls an unapproved location match a candidate, not a link', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([
      imported({ id: 'obs-candidate', findingId: 'f-2', binding: 'candidate' }),
    ])
    render(<ImportedFindingsTab engagementId="eng-1" />)

    expect(await screen.findByText('Candidate')).toBeInTheDocument()
    expect(screen.queryByText('Approved')).not.toBeInTheDocument()
    // The explanation lives in a tooltip, and its text is also exposed to a screen reader.
    expect(screen.getByText(/not a decision that they are/i)).toBeInTheDocument()
  })

  it('calls a recorded decision approved and names the finding it was made onto', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([
      imported({ id: 'obs-approved', findingId: 'f-1', binding: 'approved', approvedFindingId: 'f-1', bindingVersion: 2 }),
    ])
    render(<ImportedFindingsTab engagementId="eng-1" />)

    expect(await screen.findByText('Approved')).toBeInTheDocument()
    expect(screen.getByText(/finding f-1 describe one issue/i)).toBeInTheDocument()
    expect(screen.getByText(/version 2/i)).toBeInTheDocument()
  })

  it('says plainly when a result is linked to nothing', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([imported({ id: 'obs-none' })])
    render(<ImportedFindingsTab engagementId="eng-1" />)

    expect(await screen.findByText('Not linked')).toBeInTheDocument()
  })

  it('shows all three states side by side without confusing them', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([
      imported({ id: 'a', title: 'Approved row', findingId: 'f-1', binding: 'approved', approvedFindingId: 'f-1', bindingVersion: 1 }),
      imported({ id: 'b', title: 'Candidate row', findingId: 'f-2', binding: 'candidate', fingerprint: 'def' }),
      imported({ id: 'c', title: 'Unlinked row', fingerprint: 'ghi' }),
    ])
    render(<ImportedFindingsTab engagementId="eng-1" />)

    const table = await screen.findByRole('table')
    expect(within(table).getByText('Approved')).toBeInTheDocument()
    expect(within(table).getByText('Candidate')).toBeInTheDocument()
    expect(within(table).getByText('Not linked')).toBeInTheDocument()
  })
})

describe('ImportedFindingsTab decide action', () => {
  beforeEach(() => vi.resetAllMocks())

  // Without an entry point the feature is a badge that never changes: every row reads Candidate for
  // ever and only curl can decide anything.
  it('offers Approve on a candidate and Change on an approved row', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([
      imported({ id: 'a', title: 'Candidate row', findingId: 'f-2', binding: 'candidate' }),
      imported({ id: 'b', title: 'Approved row', findingId: 'f-1', binding: 'approved', approvedFindingId: 'f-1', bindingVersion: 1, fingerprint: 'def' }),
    ])
    render(<ImportedFindingsTab engagementId="eng-1" />)

    // The accessible name names the row, so a screen reader hearing a list of buttons can tell them apart.
    expect(await screen.findByRole('button', { name: /^Approve Candidate row onto a finding$/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Change the approved finding for Approved row$/ })).toBeInTheDocument()
  })

  it('records a decision with the reason, and refuses to submit without one', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([
      imported({ id: 'a', findingId: 'f-2', binding: 'candidate' }),
    ])
    vi.mocked(api.findings).mockResolvedValue([
      { id: 'f-2', title: 'Plaintext transport in client' } as never,
    ])
    vi.mocked(api.bindObservation).mockResolvedValue({} as never)
    render(<ImportedFindingsTab engagementId="eng-1" />)

    await userEvent.click(await screen.findByRole('button', { name: /^Approve / }))
    const submit = await screen.findByRole('button', { name: 'Record the decision' })
    // A binding with no reason is indistinguishable from the automatic merge this surface prevents.
    expect(submit).toBeDisabled()

    await userEvent.type(screen.getByPlaceholderText('Why these two describe one issue'), 'confirmed by hand')
    expect(submit).toBeEnabled()
    await userEvent.click(submit)

    expect(api.bindObservation).toHaveBeenCalledWith('eng-1', 'a', {
      findingId: 'f-2',
      reason: 'confirmed by hand',
    })
  })

  // A change has to name the version it replaces, or a decision made in between is overwritten silently.
  it('sends the version in force when changing an approved row', async () => {
    vi.mocked(api.listImportedFindings).mockResolvedValue([
      imported({ id: 'a', findingId: 'f-1', binding: 'approved', approvedFindingId: 'f-1', bindingVersion: 3 }),
    ])
    vi.mocked(api.findings).mockResolvedValue([
      { id: 'f-1', title: 'First finding' } as never,
      { id: 'f-9', title: 'Second finding' } as never,
    ])
    vi.mocked(api.bindObservation).mockResolvedValue({} as never)
    render(<ImportedFindingsTab engagementId="eng-1" />)

    await userEvent.click(await screen.findByRole('button', { name: /^Change the approved finding/ }))
    await userEvent.type(screen.getByPlaceholderText('Why these two describe one issue'), 'the first match was a coincidence')
    await userEvent.click(screen.getByRole('button', { name: 'Replace the decision' }))

    expect(api.bindObservation).toHaveBeenCalledWith('eng-1', 'a', {
      findingId: 'f-1',
      reason: 'the first match was a coincidence',
      expectedVersion: 3,
    })
  })
})
