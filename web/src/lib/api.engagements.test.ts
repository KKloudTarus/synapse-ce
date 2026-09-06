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

  it('runEmulation posts the target and maps the tag-less run summary defensively', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        run: { ID: 'emu-1', Target: 'asset-1', Coverage: [{ TechniqueID: 'T1', Executed: true }, { TechniqueID: 'T2', Executed: false }] },
        coverage: { Coverage: [], Bonus: [], Gaps: [] },
      }),
    } as Response)
    const res = await api.runEmulation('eng-1', 'asset-1')
    expect(res).toEqual({ runId: 'emu-1', techniques: 2, executed: 1 })
    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body as string)).toEqual({ target: 'asset-1' })
  })


  it('rehearseChain posts snake-cased steps and maps the result', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ chain_id: 'chain-1', state: 'succeeded', steps: 2, simulated: true }),
    } as Response)
    const res = await api.rehearseChain('eng-1', [
      { technique: 'recon.service_banner', target: 'asset-1', blastRadius: 'read_only' },
      { technique: 'x.state', target: 'asset-2', blastRadius: 'state_changing', cleanup: ['undo'], cleanupVerification: 'check' },
    ])
    expect(res).toEqual({ chainId: 'chain-1', state: 'succeeded', steps: 2, simulated: true })
    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(opts.method).toBe('POST')
    const sent = JSON.parse(opts.body as string)
    expect(sent.steps[0]).toEqual({ technique: 'recon.service_banner', target: 'asset-1', blast_radius: 'read_only', cleanup: [], cleanup_verification: '' })
    expect(sent.steps[1]).toEqual({ technique: 'x.state', target: 'asset-2', blast_radius: 'state_changing', cleanup: ['undo'], cleanup_verification: 'check' })
  })

})
