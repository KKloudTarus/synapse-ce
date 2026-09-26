import { act, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../lib/api'
import { NotificationBell } from './NotificationBell'

vi.mock('../../lib/api', () => ({
  api: { inboxUnread: vi.fn() },
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

afterEach(() => {
  vi.useRealTimers()
})

describe('NotificationBell', () => {
  it('keeps the newest unread count when an older request finishes last', async () => {
    vi.useFakeTimers()
    let resolveOlder: (value: { unread: number }) => void = () => {}
    vi.mocked(api.inboxUnread)
      .mockImplementationOnce(() => new Promise((resolve) => { resolveOlder = resolve }))
      .mockResolvedValueOnce({ unread: 4 })
    render(<MemoryRouter><NotificationBell /></MemoryRouter>)
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    await act(async () => { resolveOlder({ unread: 1 }) })
    expect(screen.getByRole('link', { name: 'Notifications, 4 unread' })).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
  })

  it('stops polling when personal inbox is not served', async () => {
    vi.useFakeTimers()
    vi.mocked(api.inboxUnread).mockRejectedValue(new ApiError(404, 'missing'))
    render(<MemoryRouter><NotificationBell /></MemoryRouter>)
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByRole('link', { name: /Notifications/ })).not.toBeInTheDocument()
    await act(async () => { await vi.advanceTimersByTimeAsync(60000) })
    expect(api.inboxUnread).toHaveBeenCalledTimes(1)
  })
})
