import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../../lib/api'
import { ProfilePage } from './ProfilePage'

vi.mock('../../lib/api', () => ({
  api: { listMyContacts: vi.fn(), addMyEmail: vi.fn(), deleteMyContact: vi.fn(), requestMyContactVerification: vi.fn(), verifyMyContact: vi.fn() },
  ApiError: class ApiError extends Error { constructor(public status: number, message: string) { super(message) } },
}))

const pending = { id:'contact-1',kind:'email',source:'manual',value:'alice@example.com',version:1,created_at:'2026-09-26T00:00:00Z',updated_at:'2026-09-26T00:00:00Z' }

describe('ProfilePage', () => {
  beforeEach(() => { vi.resetAllMocks() })

  it('shows a pending contact, queues verification, and confirms it', async () => {
    vi.mocked(api.listMyContacts).mockResolvedValueOnce([pending] as never).mockResolvedValueOnce([pending] as never).mockResolvedValueOnce([{...pending,verified_at:'2026-09-26T00:05:00Z'}] as never)
    vi.mocked(api.requestMyContactVerification).mockResolvedValue(undefined)
    vi.mocked(api.verifyMyContact).mockResolvedValue({...pending,verified_at:'2026-09-26T00:05:00Z'} as never)
    render(<ProfilePage />)
    expect(await screen.findByText('Pending verification')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button',{name:'Send verification code'}))
    expect(await screen.findByText('Verification email queued. Check your inbox.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Eight-digit code for alice@example.com'),{target:{value:'01234567'}})
    fireEvent.click(screen.getByRole('button',{name:'Verify'}))
    await waitFor(() => expect(api.verifyMyContact).toHaveBeenCalledWith('contact-1','01234567'))
    expect(await screen.findByText('Verified')).toBeInTheDocument()
  })

  it('distinguishes an unavailable deployment from an empty contact list', async () => {
    vi.mocked(api.listMyContacts).mockRejectedValue(new ApiError(404,'not found'))
    render(<ProfilePage />)
    expect(await screen.findByText('Personal contacts are unavailable on this deployment.')).toBeInTheDocument()
    expect(screen.queryByText('No email addresses yet.')).not.toBeInTheDocument()
  })
})
