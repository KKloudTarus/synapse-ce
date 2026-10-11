import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../lib/api'
import { AssigneeReview } from './AssigneeReview'

vi.mock('../../lib/api', () => ({
  api: { me: vi.fn(), assigneeReview: vi.fn() },
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
      this.name = 'ApiError'
    }
  },
}))

const row = {
  engagement_id: 'eng/1',
  finding_id: 'finding/1',
  legacy_assignee: 'Alex',
  reason: 'ambiguous',
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AssigneeReview />
    </MemoryRouter>,
  )
}

describe('AssigneeReview', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('does not load the review queue for a member', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'member' } as never)
    renderPage()
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
    expect(api.assigneeReview).not.toHaveBeenCalled()
  })

  it('links an ambiguous label to the finding and loads the next page', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.assigneeReview)
      .mockResolvedValueOnce({
        items: [row],
        next: { engagement_id: 'eng/1', finding_id: 'finding/1' },
      })
      .mockResolvedValueOnce({
        items: [{ ...row, finding_id: 'finding/2', legacy_assignee: 'Pat', reason: 'unmatched' }],
        next: null,
      })
    renderPage()
    expect(await screen.findByText(/Several users share this exact name/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open finding' })).toHaveAttribute(
      'href',
      '/engagements/eng%2F1/findings#finding-finding%2F1',
    )
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText(/No user in this tenant has this exact name/)).toBeInTheDocument()
    expect(api.assigneeReview).toHaveBeenLastCalledWith({ engagement_id: 'eng/1', finding_id: 'finding/1' })
  })

  it('shows an empty queue and a denied response without inventing users', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.assigneeReview).mockResolvedValueOnce({ items: [], next: null })
    const { unmount } = renderPage()
    expect(await screen.findByText('No unresolved assignees')).toBeInTheDocument()
    unmount()
    vi.mocked(api.assigneeReview).mockRejectedValueOnce(new ApiError(403, 'forbidden'))
    renderPage()
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
    expect(screen.queryByText('Alex')).not.toBeInTheDocument()
  })
})
