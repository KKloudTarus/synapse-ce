import { req } from './client'

export type InboxItem = {
  id: string
  event_id: string
  event_type: string
  title: string
  summary: string
  link_path: string
  created_at: string
  read_at?: string
}

export type InboxPage = { items: InboxItem[]; next?: string }

export type InboxPreference = {
  event_type: string
  channel: string
  state: 'inherit' | 'enabled' | 'disabled'
  revision: number
  mandatory: boolean
  available: boolean
  reason?: string
}

export const inboxApi = {
  inboxPage: (cursor?: string, unread = false, signal?: AbortSignal): Promise<InboxPage> => {
    const params = new URLSearchParams({ limit: '25' })
    if (cursor) params.set('cursor', cursor)
    if (unread) params.set('unread', 'true')
    return req(`/me/inbox?${params}`, signal ? { signal } : undefined)
  },
  inboxUnread: (signal?: AbortSignal): Promise<{ unread: number }> => req('/me/inbox/unread', signal ? { signal } : undefined),
  markInboxRead: (id: string): Promise<void> => req(`/me/inbox/${encodeURIComponent(id)}/read`, { method: 'POST' }),
  markInboxAllRead: (): Promise<void> => req('/me/inbox/read', { method: 'POST' }),
  inboxPreferences: (signal?: AbortSignal): Promise<{ items: InboxPreference[] }> => req('/me/notification-preferences', signal ? { signal } : undefined),
  saveInboxPreference: (input: Pick<InboxPreference, 'event_type' | 'channel' | 'state' | 'revision'>): Promise<InboxPreference> =>
    req('/me/notification-preferences', { method: 'PUT', body: JSON.stringify(input) }),
}
