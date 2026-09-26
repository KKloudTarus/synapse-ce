import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { InboxPage } from './InboxPage'

vi.mock('../../lib/api', () => ({
  api: {
    inboxPage: vi.fn(),
    inboxPreferences: vi.fn(),
    markInboxRead: vi.fn(),
    markInboxAllRead: vi.fn(),
    saveInboxPreference: vi.fn(),
  },
}))

const item = {
  id: 'n1', event_id: 'e1', event_type: 'finding.ownership_changed', title: 'Finding ownership changed',
  summary: 'A finding changed.', link_path: '/engagements/eng%2F1/findings#finding-f1', created_at: '2026-09-26T00:00:00Z',
}

describe('InboxPage', () => {
  beforeEach(() => { vi.resetAllMocks() })

  it('opens an internal finding link and refuses an external event url', async () => {
    vi.mocked(api.inboxPage).mockResolvedValue({ items: [item, { ...item, id: 'n2', title: 'External', link_path: 'https://evil.example/phish' }] })
    vi.mocked(api.inboxPreferences).mockResolvedValue({ items: [] })
    vi.mocked(api.markInboxRead).mockResolvedValue()
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    expect(await screen.findByRole('link', { name: 'Open' })).toHaveAttribute('href', item.link_path)
    expect(screen.getByText('No linked page')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('link', { name: 'Open' }))
    expect(api.markInboxRead).toHaveBeenCalledWith('n1')
  })

  it('reloads after mark all instead of guessing the new count', async () => {
    vi.mocked(api.inboxPage).mockResolvedValueOnce({ items: [item] }).mockResolvedValueOnce({ items: [{ ...item, read_at: '2026-09-26T01:00:00Z' }] })
    vi.mocked(api.inboxPreferences).mockResolvedValue({ items: [] })
    vi.mocked(api.markInboxAllRead).mockResolvedValue()
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Mark all read' }))
    expect(await screen.findByText('Finding ownership changed')).toBeInTheDocument()
    expect(api.markInboxAllRead).toHaveBeenCalledTimes(1)
    expect(api.inboxPage).toHaveBeenCalledTimes(2)
  })

  it('keeps a mandatory channel locked and saves an explicit mute', async () => {
    vi.mocked(api.inboxPage).mockResolvedValue({ items: [] })
    vi.mocked(api.inboxPreferences).mockResolvedValue({ items: [
      { event_type: 'notification.destination_changed', channel: 'in_app', state: 'inherit', revision: 0, mandatory: true, available: true },
      { event_type: 'finding.ownership_changed', channel: 'email', state: 'inherit', revision: 2, mandatory: false, available: true },
      { event_type: 'finding.ownership_changed', channel: 'slack', state: 'disabled', revision: 0, mandatory: false, available: false, reason: 'Slack direct messages are not available yet.' },
    ] })
    vi.mocked(api.saveInboxPreference).mockResolvedValue({ event_type: 'finding.ownership_changed', channel: 'email', state: 'disabled', revision: 3, mandatory: false, available: true })
    render(<MemoryRouter><InboxPage /></MemoryRouter>)
    expect(await screen.findByText('In-app delivery is required.')).toBeInTheDocument()
    expect(screen.getByText('Slack direct messages are not available yet.')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'finding.ownership_changed email' }), { target: { value: 'disabled' } })
    expect(await screen.findByDisplayValue('Disabled')).toBeInTheDocument()
    expect(api.saveInboxPreference).toHaveBeenCalledWith(expect.objectContaining({ channel: 'email', state: 'disabled', revision: 2 }))
  })
})