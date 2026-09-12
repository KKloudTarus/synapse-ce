import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { OwnershipFinding } from '../../lib/api/ownership'
import { OwnershipInbox } from './OwnershipInbox'

vi.mock('../../lib/api', () => ({
  api: {
    ownershipCapability: vi.fn(), me: vi.fn(), ownershipTeams: vi.fn(),
    listEngagements: vi.fn(), ownershipInbox: vi.fn(), bulkOwnership: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(public status: number, message: string) { super(message) }
  },
}))

const capability = { enabled: true, mode: 'enforce' as const, routing_available: true }
const finding = (id: string, engagement = 'eng-1'): OwnershipFinding => ({
  id, engagement_id: engagement, title: `Finding ${engagement}/${id}`, severity: 'critical', status: 'open', kind: 'sast', version: 3,
  assignment: { mode: 'auto', revision: 2, manual_generation: 1 }, resolution: 'unresolved', reason: 'no_matching_owner',
})

describe('OwnershipInbox', () => {
  beforeEach(() => {
    vi.mocked(api.ownershipCapability).mockResolvedValue(capability)
    vi.mocked(api.me).mockResolvedValue({ id: 'user-1', role: 'member' } as never)
    vi.mocked(api.ownershipTeams).mockResolvedValue({ items: [] })
    vi.mocked(api.listEngagements).mockResolvedValue([])
    vi.mocked(api.ownershipInbox).mockResolvedValue({ items: [], total: 0 })
  })

  function renderInbox() {
    return render(<MemoryRouter initialEntries={['/ownership']}><OwnershipInbox /></MemoryRouter>)
  }

  it('shows an explicit empty state and degraded worker status', async () => {
    vi.mocked(api.ownershipCapability).mockResolvedValue({ ...capability, routing_available: false })
    renderInbox()

    expect(await screen.findByText('No findings match these filters.')).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('routing worker is unavailable')
  })

  it('keeps conflicted rows selected after a partially successful bulk operation', async () => {
    vi.mocked(api.ownershipInbox).mockResolvedValue({ items: [finding('one'), finding('two')], total: 2 })
    vi.mocked(api.bulkOwnership).mockResolvedValue([
      { engagement_id: 'eng-1', finding_id: 'one', status: 200 },
      { engagement_id: 'eng-1', finding_id: 'two', status: 409, error: 'conflict' },
    ])
    renderInbox()

    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select this page' }))
    fireEvent.click(screen.getByRole('button', { name: 'Apply to selected findings' }))

    await waitFor(() => expect(api.bulkOwnership).toHaveBeenCalledTimes(1))
    expect(await screen.findByText('1 updated; 1 need review.')).toBeInTheDocument()
    expect(screen.getByText(/Changed since you loaded it/)).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Select Finding eng-1/two' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Select Finding eng-1/one' })).not.toBeChecked()
    expect(api.bulkOwnership).toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ finding_id: 'two', finding_version: 3, ownership_revision: 2, manual_generation: 1 })]),
      expect.any(String),
    )
  })

  it('selects duplicate finding IDs independently across engagements', async () => {
    vi.mocked(api.ownershipInbox).mockResolvedValue({
      items: [finding('shared', 'eng-1'), finding('shared', 'eng-2')],
      total: 2,
    })
    vi.mocked(api.bulkOwnership).mockResolvedValue([
      { engagement_id: 'eng-2', finding_id: 'shared', status: 200 },
    ])
    renderInbox()

    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select Finding eng-2/shared' }))
    fireEvent.click(screen.getByRole('button', { name: 'Apply to selected findings' }))

    await waitFor(() => expect(api.bulkOwnership).toHaveBeenCalledTimes(1))
    expect(api.bulkOwnership).toHaveBeenCalledWith(
      [expect.objectContaining({ engagement_id: 'eng-2', finding_id: 'shared' })],
      expect.any(String),
    )
  })

  it('blocks administration for a non-admin while preserving the inbox link', async () => {
    const { OwnershipSettings } = await import('./OwnershipSettings')
    render(<MemoryRouter><OwnershipSettings /></MemoryRouter>)

    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'team inbox' })).toHaveAttribute('href', '/ownership')
  })
})
