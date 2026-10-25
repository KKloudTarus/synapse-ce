import { act, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { NotificationBell } from './NotificationBell'

// The bell is driven through the real API client here, so these tests pin the route it polls and
// what it does with each answer, rather than a mocked module (#1417).

let unread = 0
let status = 200
let polls = 0
// What the route actually answered, so a test can wait for the failing poll itself rather than
// for a badge that was never asked to change.
const answered: number[] = []

const server = setupServer(
  http.get('/api/v1/me/inbox/unread', () => {
    polls += 1
    if (status !== 200) return new HttpResponse('not found', { status })
    return HttpResponse.json({ unread })
  }),
)

beforeAll(() => {
  server.listen({ onUnhandledFrame: 'error' })
  server.events.on('response:mocked', ({ response }) => {
    answered.push(response.status)
  })
})
beforeEach(() => {
  unread = 0
  status = 200
  polls = 0
  answered.length = 0
})
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

function mount() {
  return render(<MemoryRouter><NotificationBell /></MemoryRouter>)
}

describe('NotificationBell over the real client', () => {
  it('polls the documented route and links to the inbox', async () => {
    unread = 2
    mount()
    await waitFor(() => expect(polls).toBe(1))
    const link = await screen.findByRole('link', { name: 'Notifications, 2 unread' })
    expect(link).toHaveAttribute('href', '/inbox')
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('shows no badge when nothing is unread', async () => {
    mount()
    await screen.findByRole('link', { name: 'Notifications, 0 unread' })
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('caps the badge and still says how many in the accessible name', async () => {
    unread = 1240
    mount()
    expect(await screen.findByRole('link', { name: 'Notifications, more than 99 unread' })).toBeInTheDocument()
    expect(screen.getByText('99+')).toBeInTheDocument()
  })

  it('disappears when the deployment does not serve a personal inbox', async () => {
    status = 404
    mount()
    await waitFor(() => expect(polls).toBe(1))
    await waitFor(() => expect(screen.queryByRole('link')).not.toBeInTheDocument())
  })

  it('keeps the last count when one poll fails on the server', async () => {
    unread = 3
    mount()
    await screen.findByRole('link', { name: 'Notifications, 3 unread' })
    await waitFor(() => expect(answered).toEqual([200]))

    // Nothing polls on its own inside a test, so the next poll is the one the component runs
    // when the tab becomes visible again.
    status = 503
    document.dispatchEvent(new Event('visibilitychange'))
    await waitFor(() => expect(polls).toBe(2))
    await waitFor(() => expect(answered).toEqual([200, 503]))
    // The rejection is handled a microtask after the response, so it has to run before the
    // badge is read: a handler that cleared the count would have done it by now.
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    // A failing poll must not blank the badge: the operator keeps the count they last had.
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Notifications, 3 unread' })).toBeInTheDocument()
  })
})
