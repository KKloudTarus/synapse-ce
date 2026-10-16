import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../lib/api'
import { BulkTicketsPanel } from './BulkTicketsPanel'

vi.mock('../../../lib/api', () => ({ api: { findingTickets: vi.fn(), me: vi.fn(), previewTicket: vi.fn(), bulkTickets: vi.fn() } }))
vi.mock('../../../lib/api/client', () => ({ newIdempotencyKey: () => 'request-key' }))

describe('BulkTicketsPanel', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(api.me).mockResolvedValue({ role: 'consultant' } as never)
    vi.mocked(api.findingTickets).mockResolvedValue({ links: [], intents: [], mappings: [{ id: 'mapping-1', projectKey: 'SEC', issueType: 'Bug', locale: 'en' }] } as never)
    vi.mocked(api.previewTicket).mockImplementation(async (_engagement, finding) => ({ fields: { project: { key: 'SEC' } }, summary: `Ticket ${finding}`, description: `Description ${finding}`, dataClass: 'summary', digest: `digest-${finding}`, mappingVersion: 1, links: [{ label: `Finding ${finding}`, url: `https://console.example/${finding}` }] }))
    vi.mocked(api.bulkTickets).mockResolvedValue([{ findingId: 'f-1', intent: { id: 'intent-1', state: 'queued', errorCode: '', version: 1, createdAt: '' } }, { findingId: 'f-2', intent: { id: 'intent-2', state: 'queued', errorCode: '', version: 1, createdAt: '' } }])
  })

  it('previews every selected finding before enabling one bulk submit', async () => {
    render(<BulkTicketsPanel engagementId="eng-1" findingIds={['f-1', 'f-2']} onDone={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Prepare previews' }))
    await waitFor(() => expect(api.previewTicket).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('Ticket f-1')).toBeInTheDocument()
    expect(screen.getByText('Ticket f-2')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Finding f-1' })).toHaveAttribute('href', 'https://console.example/f-1')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Submit 2 tickets' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Submit 2 tickets' }))
    await waitFor(() => expect(api.bulkTickets).toHaveBeenCalledWith('eng-1', 'mapping-1', [
      { findingId: 'f-1', previewDigest: 'digest-f-1', requestKey: 'request-key' },
      { findingId: 'f-2', previewDigest: 'digest-f-2', requestKey: 'request-key' },
    ]))
  })

  it('keeps the panel open and identifies rejected findings when Jira accepts only part of a batch', async () => {
    const onDone = vi.fn()
    vi.mocked(api.bulkTickets).mockResolvedValue([{ findingId: 'f-1', intent: { id: 'intent-1', state: 'queued', errorCode: '', version: 1, createdAt: '' } }, { findingId: 'f-2', errorCode: 'validation' }])
    render(<BulkTicketsPanel engagementId="eng-1" findingIds={['f-1', 'f-2']} onDone={onDone} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Prepare previews' }))
    await waitFor(() => expect(api.previewTicket).toHaveBeenCalledTimes(2))
    fireEvent.click(screen.getByRole('button', { name: 'Submit 2 tickets' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Only 1 of 2 ticket requests were recorded')
    expect(screen.getByRole('alert')).toHaveTextContent('f-2 (validation)')
    expect(onDone).not.toHaveBeenCalled()
  })

  it('rejects a selection above the bounded preview limit before calling ticket APIs', async () => {
    render(<BulkTicketsPanel engagementId="eng-1" findingIds={Array.from({ length: 51 }, (_, index) => `f-${index}`)} onDone={vi.fn()} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Select no more than 50 findings')
    expect(api.findingTickets).not.toHaveBeenCalled()
    expect(api.previewTicket).not.toHaveBeenCalled()
  })
})
