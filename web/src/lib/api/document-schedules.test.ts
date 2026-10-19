import { afterEach, describe, expect, it, vi } from 'vitest'
import { documentSchedulesApi } from './document-schedules'

afterEach(() => vi.unstubAllGlobals())

describe('document schedule API contract', () => {
  it('serializes only schedule configuration and maps the safe schedule view', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'schedule-1', source_kind: 'engagement_report', source_ref: 'engagement:eng-1', scope: 'engagement', scope_id: 'eng-1', destination: 'email', email_channel_id: 'mail-1', timezone: 'Asia/Ho_Chi_Minh', frequency: 'weekly', weekday: 1, hour: 9, minute: 30, enabled: true, version: 1, next_due_at: '2026-10-20T02:30:00Z', owner_user_id: 'must-not-map' }), { status: 201, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await documentSchedulesApi.save({ sourceKind: 'engagement_report', sourceRef: 'engagement:eng-1', scopeId: 'eng-1', destination: 'email', emailChannelId: 'mail-1', timezone: 'Asia/Ho_Chi_Minh', frequency: 'weekly', weekday: 1, hour: 9, minute: 30, enabled: true })
    expect(result).toMatchObject({ id: 'schedule-1', destination: 'email', emailChannelId: 'mail-1', timezone: 'Asia/Ho_Chi_Minh' })
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(expect.objectContaining({ source_kind: 'engagement_report', email_channel_id: 'mail-1', integration_id: '' }))
    expect(result).not.toHaveProperty('ownerUserId')
  })

  it('encodes list and CAS-disable identifiers', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    await documentSchedulesApi.list('project', 'project/one')
    await documentSchedulesApi.disable('schedule/one', 4)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/document-schedules?scope=project&scope_id=project%2Fone')
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/document-schedules/schedule%2Fone')
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ expected_version: 4 })
  })

  it('maps bounded run history without recipient or raw error fields', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 'run-1', due_at: '2026-10-20T00:00:00Z', state: 'uncertain', content_hash: 'a'.repeat(64), remote_page_id: 'page-1', remote_version: 2, uncertain_count: 1, recipient: 'must-not-map', error_code: 'must-not-map' }]), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const [run] = await documentSchedulesApi.runs('schedule/one')
    expect(run).toMatchObject({ id: 'run-1', state: 'uncertain', remotePageId: 'page-1', remoteVersion: 2, uncertainCount: 1 })
    expect(run).not.toHaveProperty('recipient')
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/document-schedules/schedule%2Fone/runs', expect.anything())
  })
})
