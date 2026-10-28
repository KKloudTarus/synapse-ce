import { afterEach, describe, expect, it, vi } from 'vitest'
import { documentsApi } from './documents'

afterEach(() => vi.unstubAllGlobals())

describe('document publishing API contract', () => {
  it('preserves the safe sharing observation without exposing queue or provider details', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 'link', restriction_status: 'restriction_lost', restriction_checked_at: '2026-10-18T07:00:00Z', restriction_check_version: 12, provider_error: 'must-not-map' }]), { status: 200 })))
    const [link] = await documentsApi.listEngagementDocuments('eng-1')
    expect(link).toMatchObject({ restrictionStatus: 'restriction_lost', restrictionCheckedAt: '2026-10-18T07:00:00Z' })
    expect(link).not.toHaveProperty('provider_error')
    expect(link).not.toHaveProperty('restriction_check_version')
  })
  it('uses derived source fields and maps only the safe publication response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ skipped: false, intent: { id: 'intent-1', state: 'pending', action: 'create', version: 1, attempts: 0, actor: 'must-not-map', progress: { storage: 'must-not-map' } } }), { status: 202, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await documentsApi.publish({ integrationId: 'confluence 1', sourceKind: 'engagement_report', scopeId: 'eng 1', sourceRef: 'engagement:eng 1', requestKey: 'request 1' })
    expect(result.intent).toMatchObject({ id: 'intent-1', state: 'pending', action: 'create' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/document-publications', expect.objectContaining({ method: 'POST' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ integration_id: 'confluence 1', source_kind: 'engagement_report', scope_id: 'eng 1', source_ref: 'engagement:eng 1', request_key: 'request 1' })
  })

  it('encodes identifiers and preserves retired link state', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 'link', integration_id: 'confluence', scope: 'engagement', scope_id: 'eng 1', source_kind: 'engagement_report', source_ref: 'engagement:eng 1', remote_url: 'https://example.test/page', content_hash: 'a'.repeat(64), retired_at: '2026-10-17T00:00:00Z' }]), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const [link] = await documentsApi.listEngagementDocuments('eng 1')
    expect(link).toMatchObject({ scopeId: 'eng 1', retiredAt: '2026-10-17T00:00:00Z' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/eng%201/documents', expect.anything())
  })

  it('resumes only a named publication with its observed version', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'intent 1', state: 'pending', action: 'create', version: 5, attempts: 5 }), { status: 202, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await documentsApi.resumePreparedPublication('intent 1', 4)
    expect(result).toMatchObject({ id: 'intent 1', state: 'pending', action: 'create', version: 5, attempts: 5 })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/document-publications/intent%201/resume', expect.objectContaining({ method: 'POST' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ version: 4 })
  })

  it('maps the frozen destination access profile from snapshot history', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify([{ id: 'snapshot-1', link_id: 'link-1', state: 'done', action: 'snapshot', version: 3, attempts: 1, access_profile: 'destination_managed_snapshot_v1', content_hash: 'a'.repeat(64), created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:01:00Z' }]), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const [snapshot] = await documentsApi.listSnapshots('link 1')
    expect(snapshot).toMatchObject({ id: 'snapshot-1', accessProfile: 'destination_managed_snapshot_v1', contentHash: 'a'.repeat(64) })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/document-links/link%201/snapshots', expect.anything())
  })
})
