import { afterEach, describe, expect, it, vi } from 'vitest'
import { projectSourceFindingsApi } from './project-source-findings'

afterEach(() => vi.unstubAllGlobals())

describe('project source finding API contract', () => {
  it('reads sanitized Project findings without retaining a hidden engagement identity', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      items: [{ ID: 'finding 1', EngagementID: 'must-not-reach-browser', Title: 'Log4Shell', Severity: 'critical', Status: 'open', Version: 4 }],
      next_cursor: 'finding 1',
    }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const page = await projectSourceFindingsApi.listProjectSourceFindings('payments source')
    const [finding] = page.items

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/projects/payments%20source/source-findings?limit=50', expect.anything())
    expect(finding).toMatchObject({ id: 'finding 1', title: 'Log4Shell', version: 4 })
    expect(finding).not.toHaveProperty('engagementId')
    expect(page.nextCursor).toBe('finding 1')
  })

  it('uses the single Project-scoped route for a deep-linked finding', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ID: 'finding 1', Title: 'Log4Shell', Status: 'open', Version: 4 }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await projectSourceFindingsApi.getProjectSourceFinding('payments source', 'finding 1')

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/projects/payments%20source/source-findings/finding%201', expect.anything())
  })

  it('uses the Project-scoped optimistic triage route', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ID: 'finding 1', Title: 'Log4Shell', Status: 'confirmed', Version: 5 }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await projectSourceFindingsApi.updateProjectSourceFindingStatus('payments source', 'finding 1', 'confirmed', 4, 'validated')

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/projects/payments%20source/source-findings/finding%201', expect.objectContaining({ method: 'PATCH' }))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ status: 'confirmed', note: 'validated', version: 4 })
  })
})
