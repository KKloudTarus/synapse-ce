import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import { notificationsApi } from './notifications'

describe('notification API', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch')
  })
  afterEach(() => vi.restoreAllMocks())
  function respond(body: unknown, status = 200) {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: status < 400,
      status,
      json: async () => body,
    } as Response)
  }
  it('distinguishes an absent framework from an empty tenant', async () => {
    respond({ error: 'not found' }, 404)
    expect(await notificationsApi.listNotificationChannels()).toBeNull()
    respond({ items: [] })
    expect(await notificationsApi.listNotificationChannels()).toEqual([])
  })
  it('queues a test without claiming delivery success', async () => {
    respond({ delivery_id: 'd1', state: 'pending' }, 202)
    expect(await notificationsApi.testNotificationChannel('channel')).toEqual({
      delivery_id: 'd1',
      state: 'pending',
    })
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/notifications/channels/channel/test'),
      expect.objectContaining({ method: 'POST' }),
    )
  })
  it('sends only rule input fields when toggling a loaded rule', async () => {
    respond({})
    await notificationsApi.updateNotificationRule('r', {
      id: 'r',
      name: 'High',
      enabled: false,
      event_type: 'incident.created',
      channel_ids: ['c'],
      revision: 2,
      created_at: 'date',
    } as never)
    const options = vi.mocked(fetch).mock.calls[0][1]
    const body = JSON.parse(String(options?.body))
    expect(body).toMatchObject({ revision: 2, enabled: false })
    expect(body).not.toHaveProperty('id')
    expect(body).not.toHaveProperty('created_at')
  })
  it('encodes delivery cursor and filters', async () => {
    respond({ items: [], next: 'next' })
    await notificationsApi.notificationDeliveryPage({
      cursor: '2026-01-01T00:00:00Z|d',
      state: 'retrying',
      event_type: 'scan.completed',
    })
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('state=retrying'),
      expect.anything(),
    )
  })
})
