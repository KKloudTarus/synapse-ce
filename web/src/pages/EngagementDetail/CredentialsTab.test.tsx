import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import type { EngagementCredential } from '../../lib/api'
import { CredentialsTab } from './CredentialsTab'

vi.mock('../../lib/api', () => ({
  api: {
    engagementCredentials: vi.fn(),
    setEngagementCredential: vi.fn(),
    deleteEngagementCredential: vi.fn(),
  },
}))

const CREDS: EngagementCredential[] = [
  { name: 'registry_token', createdAt: '2026-02-10T00:00:00Z', updatedAt: '2026-02-18T00:00:00Z' },
]

describe('CredentialsTab', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists stored credentials and keeps the add form collapsed', async () => {
    vi.mocked(api.engagementCredentials).mockResolvedValue(CREDS)
    render(<CredentialsTab engagementId="eng-001" />)

    expect(await screen.findByText('registry_token')).toBeInTheDocument()
    // The form is collapsed when credentials already exist; an Add button reveals it.
    expect(screen.queryByPlaceholderText('Enter a placeholder name')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add' })).toBeInTheDocument()
  })

  it('stores a new credential (write-only value) from the open form', async () => {
    vi.mocked(api.engagementCredentials).mockResolvedValue([])
    vi.mocked(api.setEngagementCredential).mockResolvedValue(undefined)
    render(<CredentialsTab engagementId="eng-001" />)

    // Empty state opens the form by default.
    await userEvent.type(await screen.findByPlaceholderText('Enter a placeholder name'), 'npm_token')
    await userEvent.type(screen.getByPlaceholderText('Paste the secret value'), 's3cr3t')
    await userEvent.click(screen.getByRole('button', { name: /Store credential/ }))

    await waitFor(() => expect(api.setEngagementCredential).toHaveBeenCalledWith('eng-001', 'npm_token', 's3cr3t'))
  })

  it('deletes a credential via an inline confirm', async () => {
    vi.mocked(api.engagementCredentials).mockResolvedValue(CREDS)
    vi.mocked(api.deleteEngagementCredential).mockResolvedValue(undefined)
    render(<CredentialsTab engagementId="eng-001" />)

    await userEvent.click(await screen.findByRole('button', { name: /Delete credential registry_token/ }))
    // An inline confirm appears (no browser dialog).
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(api.deleteEngagementCredential).toHaveBeenCalledWith('eng-001', 'registry_token'))
  })

  it('disables store for an invalid placeholder name', async () => {
    vi.mocked(api.engagementCredentials).mockResolvedValue([])
    render(<CredentialsTab engagementId="eng-001" />)
    await userEvent.type(await screen.findByPlaceholderText('Enter a placeholder name'), 'bad name!')
    await userEvent.type(screen.getByPlaceholderText('Paste the secret value'), 'x')
    expect(screen.getByRole('button', { name: /Store credential/ })).toBeDisabled()
    expect(api.setEngagementCredential).not.toHaveBeenCalled()
  })
})
