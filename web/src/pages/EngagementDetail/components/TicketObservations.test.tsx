import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api } from '../../../lib/api'
import { TicketObservations } from './TicketObservations'

vi.mock('../../../lib/api', () => ({ api: { ticketObservations: vi.fn() } }))
beforeEach(() => vi.resetAllMocks())

it('shows loading then an empty observation view', async () => {
  vi.mocked(api.ticketObservations).mockResolvedValue({ observations: [], proposals: [], comments: [] })
  render(<TicketObservations engagementId="eng" findingId="finding" />)
  expect(screen.getByText('Loading Jira observations…')).toBeInTheDocument()
  await screen.findByText('No Jira observations yet.')
})

it('renders external comments literally and leaves proposals for human review', async () => {
  vi.mocked(api.ticketObservations).mockResolvedValue({ observations: [{ remoteId: 'SEC-1', category: 'done', deletedOrUnreadable: false, checkedAt: '' }], proposals: [{ id: 'proposal', remoteId: 'SEC-1', state: 'pending', observedAt: '', resolutionContext: 'Fixed' }], comments: [{ id: 'comment', remoteId: 'SEC-1', origin: 'external', body: '<img src=x onerror=alert(1)> @admin [~all] Đã kiểm tra', createdAt: '' }] })
  const { container } = render(<TicketObservations engagementId="eng" findingId="finding" />)
  await screen.findByText('SEC-1 · Retest requested · pending')
  expect(screen.getByText(/record a retest through the finding workflow/)).toBeInTheDocument()
  expect(screen.getByText('Resolution context: Fixed')).toBeInTheDocument()
  expect(screen.getByText('<img src=x onerror=alert(1)> @admin [~all] Đã kiểm tra')).toBeInTheDocument()
  expect(container.querySelector('img')).toBeNull()
  expect(screen.queryByRole('button', { name: /accept|remediated/i })).not.toBeInTheDocument()
})

it('shows permission denial without prior finding content', async () => {
  vi.mocked(api.ticketObservations).mockRejectedValue(new Error('You do not have permission to view this finding.'))
  render(<TicketObservations engagementId="eng" findingId="finding" />)
  await screen.findByText('You do not have permission to view this finding.')
  expect(screen.queryByText('No Jira observations yet.')).not.toBeInTheDocument()
})

it('ignores a late response from the previous finding', async () => {
  let finish!: (value: Awaited<ReturnType<typeof api.ticketObservations>>) => void
  vi.mocked(api.ticketObservations).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve })).mockResolvedValue({ observations: [], proposals: [], comments: [] })
  const { rerender } = render(<TicketObservations engagementId="eng" findingId="first" />)
  rerender(<TicketObservations engagementId="eng" findingId="second" />)
  await screen.findByText('No Jira observations yet.')
  finish({ observations: [], proposals: [{ id: 'old', remoteId: 'OLD-1', state: 'pending', observedAt: '' }], comments: [] })
  await waitFor(() => expect(screen.queryByText(/OLD-1/)).not.toBeInTheDocument())
})
