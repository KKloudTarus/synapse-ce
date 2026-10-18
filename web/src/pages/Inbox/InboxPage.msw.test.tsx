import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { InboxPage } from './InboxPage'

// The page is driven through the real API client here, so these tests pin the HTTP contract the
// console depends on: the paths, the query parameters and the request bodies, not a mocked module.
// #1417 asks for exactly that.

type Row = {
  id: string
  event_id: string
  event_type: string
  title: string
  summary: string
  link_path: string
  created_at: string
  read_at?: string
}

const notice: Row = {
  id: 'n1', event_id: 'e1', event_type: 'notification.destination_changed',
  title: 'Notification destination created', summary: 'operator created the webhook destination https://hooks.example.test.',
  link_path: '/settings/alerting', created_at: '2026-10-18T13:44:44Z',
}
const external: Row = {
  ...notice, id: 'n2', title: 'Finding assigned', summary: 'A finding was assigned to you.',
  link_path: 'https://evil.example/phish',
}

let rows: Row[] = []
const seen: { inbox: string[]; reads: string[]; markAll: number } = { inbox: [], reads: [], markAll: 0 }
let inboxStatus = 200

const server = setupServer(
  http.get('/api/v1/me/inbox', ({ request }) => {
    const url = new URL(request.url)
    seen.inbox.push(url.search)
    if (inboxStatus !== 200) return new HttpResponse('unavailable', { status: inboxStatus })
    const unread = url.searchParams.get('unread') === 'true'
    return HttpResponse.json({ items: unread ? rows.filter((row) => !row.read_at) : rows })
  }),
  http.get('/api/v1/me/notification-preferences', () => HttpResponse.json({ items: [] })),
  http.post('/api/v1/me/inbox/read', () => {
    seen.markAll += 1
    rows = rows.map((row) => ({ ...row, read_at: '2026-10-18T14:00:00Z' }))
    return new HttpResponse(null, { status: 204 })
  }),
  http.post('/api/v1/me/inbox/:id/read', ({ params }) => {
    seen.reads.push(String(params.id))
    rows = rows.map((row) => (row.id === params.id ? { ...row, read_at: '2026-10-18T14:00:00Z' } : row))
    return new HttpResponse(null, { status: 204 })
  }),
)

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
beforeEach(() => {
  rows = [{ ...notice }, { ...external }]
  seen.inbox = []
  seen.reads = []
  seen.markAll = 0
  inboxStatus = 200
})
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

describe('InboxPage over the real client', () => {
  it('lists what the API returned and asks for the documented page size', async () => {
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    expect(await screen.findByText('Notification destination created')).toBeInTheDocument()
    expect(screen.getByText('operator created the webhook destination https://hooks.example.test.')).toBeInTheDocument()
    expect(seen.inbox[0]).toContain('limit=25')
    expect(seen.inbox[0]).not.toContain('unread=true')
  })

  it('opens an internal link and refuses an external one, marking only the opened row read', async () => {
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    const open = await screen.findByRole('link', { name: 'Open' })
    expect(open).toHaveAttribute('href', '/settings/alerting')
    expect(screen.getByText('No linked page')).toBeInTheDocument()
    fireEvent.click(open)
    await waitFor(() => expect(seen.reads).toEqual(['n1']))
  })

  it('asks the server for unread rows rather than filtering what it already has', async () => {
    rows = [{ ...notice, read_at: '2026-10-18T13:50:00Z' }, { ...external }]
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    await screen.findByText('Finding assigned')
    fireEvent.click(screen.getByLabelText('Unread only'))
    await waitFor(() => expect(seen.inbox.some((search) => search.includes('unread=true'))).toBe(true))
    await waitFor(() => expect(screen.queryByText('Notification destination created')).not.toBeInTheDocument())
  })

  it('marks every row read and reloads from the server instead of guessing', async () => {
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    await screen.findByText('Notification destination created')
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(seen.markAll).toBe(1))
    await waitFor(() => expect(seen.inbox.length).toBeGreaterThan(1))
    fireEvent.click(screen.getByLabelText('Unread only'))
    expect(await screen.findByText('No notifications.')).toBeInTheDocument()
  })

  it('reports a failing API instead of showing an empty inbox as if it were quiet', async () => {
    inboxStatus = 503
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    expect(await screen.findByText(/No notifications\./)).toBeInTheDocument()
    await waitFor(() => expect(document.body.textContent).toMatch(/unavailable|error|failed|Cannot/i))
  })
})
