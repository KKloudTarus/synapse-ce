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
  it('surfaces a 404 instead of reading it as a disabled framework', async () => {
    // Whether notifications are on comes from the `notifications` capability (#1350).
    respond({ error: 'not found' }, 404)
    await expect(notificationsApi.listNotificationChannels()).rejects.toThrow()
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
  it('resumes a paused channel with only its revision', async () => {
    respond({ id: 'c/1', revision: 5, health: { state: 'active', consecutive_failures: 0 } })
    const resumed = await notificationsApi.resumeNotificationChannel('c/1', 4)
    expect(resumed.health?.state).toBe('active')
    const [url, options] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toContain('/notifications/channels/c%2F1/resume')
    expect(options).toMatchObject({ method: 'POST' })
    expect(JSON.parse(String(options?.body))).toEqual({ revision: 4 })
  })
  it('reads the pause and resume history', async () => {
    respond({ items: [{ id: 'h1', channel_id: 'c1', action: 'paused', failures: 5, actor: 'system', occurred_at: 'date' }] })
    const items = await notificationsApi.listNotificationChannelHealthEvents('c1')
    expect(items).toHaveLength(1)
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toContain('/notifications/channels/c1/health-events')
    respond({})
    expect(await notificationsApi.listNotificationChannelHealthEvents('c1')).toEqual([])
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
  it('resends the team scope when updating an ownership rule', async () => {
    // The server replaces the rule on PATCH and rejects an ownership rule without a team scope.
    respond({})
    await notificationsApi.updateNotificationRule('r', {
      name: 'Ownership',
      enabled: false,
      event_type: 'finding.ownership_changed',
      team_ids: ['pay', 'ops'],
      channel_ids: ['c'],
      revision: 4,
    })
    respond({})
    await notificationsApi.updateNotificationRule('r', {
      name: 'Ownership',
      enabled: true,
      event_type: 'finding.ownership_changed',
      all_teams: true,
      channel_ids: ['c'],
      revision: 5,
    })
    const [teams, all] = vi
      .mocked(fetch)
      .mock.calls.map(([, options]) => JSON.parse(String(options?.body)))
    expect(teams).toMatchObject({ team_ids: ['pay', 'ops'], revision: 4 })
    expect(teams).not.toHaveProperty('all_teams')
    expect(all).toMatchObject({ all_teams: true, revision: 5 })
    expect(all).not.toHaveProperty('team_ids')
  })
  it('lists bindable templates of one family and previews a resolution', async () => {
    respond({ items: [{ id: 't1', family: 'chat' }] })
    expect(await notificationsApi.listBindableNotificationTemplates('chat')).toHaveLength(1)
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toContain('/notifications/templates?family=chat&status=active')
    respond({ tier: 'channel', event_type: 'scan.completed', locale: 'en', locale_source: 'default' })
    const resolution = await notificationsApi.previewNotificationTemplateResolution('c/1', 'scan.completed')
    expect(resolution.tier).toBe('channel')
    expect(String(vi.mocked(fetch).mock.calls[1][0])).toContain('/notifications/channels/c%2F1/template-resolution?event_type=scan.completed')
  })
  it('sends a channel binding only when given', async () => {
    respond({})
    await notificationsApi.updateNotificationChannel('c1', { name: 'ops', type: 'slack', enabled: true, revision: 2, template_id: '', locale: 'vi' })
    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toMatchObject({ template_id: '', locale: 'vi' })
    respond({})
    await notificationsApi.updateNotificationChannel('c1', { name: 'ops', type: 'slack', enabled: true, revision: 3 })
    const body = JSON.parse(String(vi.mocked(fetch).mock.calls[1][1]?.body))
    expect(body).not.toHaveProperty('template_id')
    expect(body).not.toHaveProperty('locale')
  })
  it('reads and updates an engagement external notification limit with its revision', async () => {
    respond({ engagement_id: 'eng/1', external_notifications: 'signal', revision: 4 })
    expect(
      await notificationsApi.getNotificationEngagementSetting('eng/1'),
    ).toMatchObject({ external_notifications: 'signal', revision: 4 })
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toContain(
      '/notifications/engagements/eng%2F1/settings',
    )
    respond({ engagement_id: 'eng/1', external_notifications: 'none', revision: 5 })
    await notificationsApi.updateNotificationEngagementSetting('eng/1', {
      external_notifications: 'none',
      revision: 4,
    })
    const [url, options] = vi.mocked(fetch).mock.calls[1]
    expect(String(url)).toContain('/notifications/engagements/eng%2F1/settings')
    expect(options).toMatchObject({ method: 'PUT' })
    expect(JSON.parse(String(options?.body))).toEqual({
      external_notifications: 'none',
      revision: 4,
    })
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
  it('redrives one delivery with its reason and observed queue fence', async () => {
    respond({ id: 'd/1', state: 'pending', redrive_fence: 9 })
    await notificationsApi.redriveNotificationDelivery('d/1', 'Corrected endpoint', 7)
    const [url, options] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toContain('/api/v1/notifications/deliveries/d%2F1/redrive')
    expect(options).toMatchObject({ method: 'POST' })
    expect(JSON.parse(String(options?.body))).toEqual({
      reason: 'Corrected endpoint',
      expected_fence: 7,
    })
  })
})
