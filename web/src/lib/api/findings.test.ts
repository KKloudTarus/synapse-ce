import { afterEach, describe, expect, it, vi } from 'vitest'
import { findingsApi, mapFinding } from './findings'

afterEach(() => vi.restoreAllMocks())

describe('mapFinding', () => {
  it('preserves Vulnerability Intelligence provenance from the API', () => {
    const finding = mapFinding({
      ID: 'finding-1',
      AdvisoryID: 'CVE-2026-12346',
      OccurrenceID: 'occurrence-1',
      Sources: ['nvd', 'cisa_kev', { untrusted: true }],
      Confidence: 'high',
      FixedVersion: '2.0.1',
      DetectionState: 'detected',
      EvaluatedAt: '2026-09-14T00:00:00Z',
    })

    expect(finding).toMatchObject({
      advisoryId: 'CVE-2026-12346',
      occurrenceId: 'occurrence-1',
      sources: ['nvd', 'cisa_kev'],
      confidence: 'high',
      fixedVersion: '2.0.1',
      detectionState: 'detected',
      evaluatedAt: '2026-09-14T00:00:00Z',
    })
  })
})

describe('addFindingComment', () => {
  it('sends only selected canonical mention IDs', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ID: 'comment-1' }), { status: 200 }))

    await findingsApi.addFindingComment('eng/1', 'finding/1', 'hello', ['user-a', 'user-b'])

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/engagements/eng%2F1/findings/finding%2F1/comments', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ body: 'hello', mention_user_ids: ['user-a', 'user-b'] }),
    }))
  })
})

describe('findingComments', () => {
  it('maps the actual handler wire shape and retains legacy uppercase mention IDs', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify([
      {
        ID: 'comment-native',
        EngagementID: 'engagement-1',
        FindingID: 'finding-1',
        Author: 'Ada',
        Body: 'Native mention',
        mention_user_ids: ['user-a'],
        CreatedAt: '2026-10-14T00:00:00Z',
      },
      {
        ID: 'comment-legacy',
        FindingID: 'finding-1',
        Author: 'Grace',
        Body: 'Legacy mention',
        MentionUserIDs: ['user-b'],
        CreatedAt: '2026-10-14T00:01:00Z',
      },
      {
        ID: 'comment-without-mentions',
        FindingID: 'finding-1',
        Author: 'Lin',
        Body: 'Legacy plain comment',
        CreatedAt: '2026-10-14T00:02:00Z',
      },
    ]), { status: 200 }))

    await expect(findingsApi.findingComments('engagement-1', 'finding-1')).resolves.toEqual([
      { id: 'comment-native', findingId: 'finding-1', author: 'Ada', body: 'Native mention', mentionUserIds: ['user-a'], createdAt: '2026-10-14T00:00:00Z' },
      { id: 'comment-legacy', findingId: 'finding-1', author: 'Grace', body: 'Legacy mention', mentionUserIds: ['user-b'], createdAt: '2026-10-14T00:01:00Z' },
      { id: 'comment-without-mentions', findingId: 'finding-1', author: 'Lin', body: 'Legacy plain comment', createdAt: '2026-10-14T00:02:00Z' },
    ])
  })
})
