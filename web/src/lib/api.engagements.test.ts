import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

// Shape from `engagementView` in internal/adapter/httpapi/resource_view.go.
const engagementWire = {
  id: 'eng-upload',
  name: 'Uploaded assessment',
  status: 'draft',
  scope: { in_scope: [], out_of_scope: [] },
}

describe('Engagements API', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  it('creates an engagement from multipart source without overriding the boundary', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 201, json: async () => engagementWire } as Response)
    const source = new File(['archive-bytes'], 'source.tar.gz', { type: 'application/gzip' })

    await api.createEngagementFromSource({
      name: 'Uploaded assessment',
      client: 'Acme',
      inScope: [],
      outOfScope: [],
      timezone: 'Asia/Ho_Chi_Minh',
    }, source)

    const init = fetchSpy.mock.calls[0][1] as RequestInit
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/engagements')
    expect(init.body).toBeInstanceOf(FormData)
    expect(init.headers).not.toHaveProperty('content-type')
    const form = init.body as FormData
    expect(form.get('source')).toBe(source)
    expect(JSON.parse(String(form.get('metadata')))).toMatchObject({
      name: 'Uploaded assessment',
      client: 'Acme',
      in_scope: [],
      timezone: 'Asia/Ho_Chi_Minh',
    })
  })

  it('maps uploaded source metadata', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        filename: 'source.zip', size: 42, sha256: 'a'.repeat(64),
        target: `uploaded-source/sha256/${'a'.repeat(64)}`,
        uploaded_by: 'operator', uploaded_at: '2026-08-28T00:00:00Z',
      }),
    } as Response)

    await expect(api.uploadedSource('eng upload')).resolves.toMatchObject({
      filename: 'source.zip', size: 42, uploadedBy: 'operator', uploadedAt: '2026-08-28T00:00:00Z',
    })
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/engagements/eng%20upload/source')
  })
})
