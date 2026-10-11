import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { ProfilePage } from './ProfilePage'

vi.mock('../../lib/api', () => ({
  api: {
    listMyContacts: vi.fn(),
    addMyEmail: vi.fn(),
    addMySlack: vi.fn(),
    linkMyTeams: vi.fn(),
    myPersonalChannels: vi.fn(),
    deleteMyContact: vi.fn(),
    requestMyContactVerification: vi.fn(),
    verifyMyContact: vi.fn(),
  },
  ApiError: class ApiError extends Error { constructor(public status: number, message: string) { super(message) } },
}))

const at = '2026-10-10T00:00:00Z'
const slackPending = { id: 'slack-1', kind: 'slack', source: 'manual', value: 'T0123:U0ADA', version: 1, created_at: at, updated_at: at }
const teamsLinked = { id: 'teams-1', kind: 'teams', source: 'manual', value: '0a0b0c0d-1111-2222-3333-444455556666', verified_at: at, version: 1, created_at: at, updated_at: at }

describe('Slack and Teams in My profile (#1419, #1420)', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.myPersonalChannels).mockResolvedValue({ slack: { available: true, workspaces: [{ team_id: 'T0123', team_name: 'Acme' }] }, teams: { available: true } })
  })

  it('adds a Slack account by member ID and verifies the code sent in Slack', async () => {
    vi.mocked(api.listMyContacts).mockResolvedValueOnce([]).mockResolvedValue([slackPending] as never)
    vi.mocked(api.addMySlack).mockResolvedValue(slackPending as never)
    vi.mocked(api.requestMyContactVerification).mockResolvedValue(undefined)
    vi.mocked(api.verifyMyContact).mockResolvedValue({ ...slackPending, verified_at: at } as never)
    render(<ProfilePage />)
    expect(await screen.findByRole('heading', { name: 'Slack' })).toBeInTheDocument()
    // Only email addresses are listed as email contacts.
    expect(screen.getByText('No email addresses yet.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Slack member ID'), { target: { value: 'u0ada' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add Slack account' }))
    await waitFor(() => expect(api.addMySlack).toHaveBeenCalledWith('T0123', 'U0ADA'))
    expect(await screen.findByText('U0ADA in Acme')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Send code in Slack' }))
    expect(await screen.findByText('Code sent as a Slack direct message.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Eight-digit code for Slack U0ADA in Acme'), { target: { value: '12345678' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() => expect(api.verifyMyContact).toHaveBeenCalledWith('slack-1', '12345678'))
  })

  it('links Teams with the code the bot sent', async () => {
    vi.mocked(api.listMyContacts).mockResolvedValueOnce([]).mockResolvedValue([teamsLinked] as never)
    vi.mocked(api.linkMyTeams).mockResolvedValue(teamsLinked as never)
    render(<ProfilePage />)
    fireEvent.change(await screen.findByLabelText('Teams link code'), { target: { value: 'abcde-fghjk' } })
    fireEvent.click(screen.getByRole('button', { name: 'Link Teams' }))
    await waitFor(() => expect(api.linkMyTeams).toHaveBeenCalledWith('abcde-fghjk'))
    expect(await screen.findByText('Microsoft Teams account linked.')).toBeInTheDocument()
    expect(screen.getByText('Teams account linked')).toBeInTheDocument()
    // The Entra object ID is not shown.
    expect(screen.queryByText(teamsLinked.value)).not.toBeInTheDocument()
  })

  it('hides Slack and Teams when the deployment cannot link them', async () => {
    vi.mocked(api.myPersonalChannels).mockResolvedValue({ slack: { available: false, workspaces: [] }, teams: { available: false } })
    vi.mocked(api.listMyContacts).mockResolvedValue([])
    render(<ProfilePage />)
    expect(await screen.findByText('No email addresses yet.')).toBeInTheDocument()
    await waitFor(() => expect(api.myPersonalChannels).toHaveBeenCalled())
    expect(screen.queryByRole('heading', { name: 'Slack' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Microsoft Teams' })).not.toBeInTheDocument()
  })
})
