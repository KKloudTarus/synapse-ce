import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { setupServer } from 'msw/node'
import { handlers } from './handlers'
import { matchGenerated } from './generated'

const server = setupServer(...handlers)
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
afterEach(() => vi.unstubAllEnvs())
const request = (path: string, method = 'GET') => fetch(new URL(`/api/v1${path}`, window.location.origin), { method })

describe('Shared dev mock contracts', () => {
  it.each(['POST', 'PATCH', 'PUT', 'DELETE'])('keeps the plain-dev %s fallback while rejecting unsupported playground writes', async method => {
    vi.stubEnv('VITE_PLAYGROUND', '')
    const dev = await request('/some/unmocked/thing', method)
    expect(dev.status).toBe(200)
    expect(await dev.json()).toEqual({ ok: true })
    vi.stubEnv('VITE_PLAYGROUND', '1')
    expect((await request('/some/unmocked/thing', method)).status).toBe(422)
  })
  it('retains generated write response shapes in plain dev', async () => {
    vi.stubEnv('VITE_PLAYGROUND', '')
    const path = '/api/v1/quality-gates/gate-1'
    const generated = matchGenerated('PUT', path)
    const result = await request('/quality-gates/gate-1', 'PUT')
    expect(result.status).toBe(200)
    expect(await result.json()).toEqual(generated.found && generated.body !== null ? generated.body : { ok: true })
  })
  it.each(['agent-sessions', 'agent-approvals', 'agent-readiness', 'agent-sessions/sess-001', 'agent-sessions/sess-001/plan', 'agent-sessions/sess-001/decisions'])('retains the %s fixture without the playground flag', async route => {
    vi.stubEnv('VITE_PLAYGROUND', '')
    const result = await request(`/engagements/eng-001/${route}`)
    expect(result.status).toBe(200)
    const body = await result.json()
    expect(body).toBeTruthy()
    expect(body.error).toBeUndefined()
  })
})
