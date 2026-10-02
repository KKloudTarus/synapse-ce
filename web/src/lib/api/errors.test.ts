import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, isCredentialInvalid, isUnauthenticated } from './errors'
import { blobDownload, discoverSession, req, setToken, setUnauthorizedHandler } from './client'

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

describe('ApiError contract parsing', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => { fetchSpy = vi.spyOn(globalThis, 'fetch'); setToken('') })
  afterEach(() => { fetchSpy.mockRestore(); setUnauthorizedHandler(() => {}); setToken('') })

  it('reads code, request_id and retryable from the error body', async () => {
    fetchSpy.mockResolvedValueOnce(respond(503, { error: 'store down', code: 'authentication_unavailable', request_id: 'req-1', retryable: true }))
    const err = await req('/aup').catch((e: unknown) => e) as ApiError

    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(503)
    expect(err.message).toBe('store down')
    expect(err.code).toBe('authentication_unavailable')
    expect(err.requestId).toBe('req-1')
    expect(err.retryable).toBe(true)
  })

  it('falls back to the X-Request-ID header and tolerates a body with only error', async () => {
    fetchSpy.mockResolvedValueOnce(respond(500, { error: 'boom' }, { 'X-Request-ID': 'hdr-9' }))
    const err = await req('/aup').catch((e: unknown) => e) as ApiError

    expect(err.code).toBeUndefined()
    expect(err.requestId).toBe('hdr-9')
    expect(err.retryable).toBe(true)
  })

  it('tolerates a non-JSON error body', async () => {
    fetchSpy.mockResolvedValueOnce(respond(502, '<html>bad gateway</html>'))
    const err = await req('/aup').catch((e: unknown) => e) as ApiError

    expect(err.message).toBe('HTTP 502')
    expect(err.retryable).toBe(true)
  })

  it('treats an unknown code as retryable on a 5xx and final on a 4xx', () => {
    expect(new ApiError(503, 'x', { code: 'future_code' }).retryable).toBe(true)
    expect(new ApiError(422, 'x', { code: 'future_code' }).retryable).toBe(false)
    expect(new ApiError(0, 'offline').retryable).toBe(true)
  })

  it('classifies only authentication_invalid, or an uncoded 401, as a rejected credential', () => {
    expect(isCredentialInvalid(new ApiError(401, 'x', { code: 'authentication_invalid' }))).toBe(true)
    expect(isCredentialInvalid(new ApiError(401, 'x'))).toBe(true)
    expect(isCredentialInvalid(new ApiError(401, 'x', { code: 'authentication_required' }))).toBe(false)
    expect(isCredentialInvalid(new ApiError(503, 'x', { code: 'authentication_unavailable' }))).toBe(false)
    expect(isCredentialInvalid(new ApiError(403, 'x', { code: 'permission_denied' }))).toBe(false)
    expect(isCredentialInvalid(new ApiError(403, 'x', { code: 'csrf_invalid' }))).toBe(false)
    expect(isCredentialInvalid(new ApiError(403, 'x', { code: 'aup_required' }))).toBe(false)
    expect(isCredentialInvalid(new ApiError(403, 'x'))).toBe(false)
    expect(isCredentialInvalid(new Error('offline'))).toBe(false)
    expect(isUnauthenticated(new ApiError(401, 'x', { code: 'authentication_required' }))).toBe(true)
  })

  it('does not call the unauthorized handler for a 503 or a 403', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    fetchSpy.mockResolvedValueOnce(respond(503, { error: 'x', code: 'authentication_unavailable', retryable: true }))
    fetchSpy.mockResolvedValueOnce(respond(403, { error: 'x', code: 'permission_denied' }))
    fetchSpy.mockResolvedValueOnce(respond(503, { error: 'x', code: 'authentication_unavailable' }))

    await req('/findings').catch(() => {})
    await req('/findings').catch(() => {})
    await blobDownload('/api/v1/export', 'export.json').catch(() => {})
    expect(handler).not.toHaveBeenCalled()
  })

  it('passes the parsed error to the unauthorized handler on a 401', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    fetchSpy.mockResolvedValueOnce(respond(401, { error: 'revoked', code: 'authentication_invalid' }))

    await req('/findings').catch(() => {})
    expect(handler).toHaveBeenCalledTimes(1)
    expect((handler.mock.calls[0][0] as ApiError).code).toBe('authentication_invalid')
  })

  it('ignores a late invalid response from a replaced bearer epoch', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    setToken('old-token')
    let resolveOld!: (response: Response) => void
    fetchSpy.mockReturnValueOnce(new Promise<Response>((resolve) => { resolveOld = resolve }))

    const oldRequest = req('/aup').catch((error: unknown) => error)
    setToken('new-token')
    fetchSpy.mockResolvedValueOnce(respond(200, { accepted: true }))
    await expect(req('/aup')).resolves.toEqual({ accepted: true })
    resolveOld(respond(401, { error: 'revoked', code: 'authentication_invalid' }))

    const oldError = await oldRequest as ApiError
    expect(oldError.code).toBe('authentication_invalid')
    expect(handler).not.toHaveBeenCalled()
    expect(fetchSpy.mock.calls[0][1]).toMatchObject({ headers: expect.objectContaining({ authorization: 'Bearer old-token' }) })
    expect(fetchSpy.mock.calls[1][1]).toMatchObject({ headers: expect.objectContaining({ authorization: 'Bearer new-token' }) })
  })

  it('notifies for an invalid response from the current bearer epoch', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    setToken('new-token')
    fetchSpy.mockResolvedValueOnce(respond(401, { error: 'revoked', code: 'authentication_invalid' }))

    await req('/aup').catch(() => {})

    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('reports an unavailable session store as an error rather than as signed out', async () => {
    fetchSpy.mockResolvedValueOnce(respond(503, { error: 'x', code: 'authentication_unavailable', retryable: true }))
    const err = await discoverSession().catch((e: unknown) => e) as ApiError

    expect(err).toBeInstanceOf(ApiError)
    expect(err.code).toBe('authentication_unavailable')
    expect(err.retryable).toBe(true)
  })

  it('retries discovery once when another tab won the session rotation', async () => {
    fetchSpy.mockResolvedValueOnce(respond(409, { error: 'session rotation conflict', code: 'conflict', request_id: 'req-409', retryable: true }))
    fetchSpy.mockResolvedValueOnce(respond(200, { authenticated: true, csrf_token: 'csrf-after-rotation' }))

    await expect(discoverSession()).resolves.toEqual({ authenticated: true, csrfToken: 'csrf-after-rotation' })
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('reports a repeated rotation conflict as a retryable error, never as signed out', async () => {
    const conflict = { error: 'session rotation conflict', code: 'conflict', request_id: 'req-409', retryable: true }
    fetchSpy.mockResolvedValueOnce(respond(409, conflict))
    fetchSpy.mockResolvedValueOnce(respond(409, conflict))

    const err = await discoverSession().catch((e: unknown) => e) as ApiError

    expect(err).toBeInstanceOf(ApiError)
    expect(err.code).toBe('conflict')
    expect(err.retryable).toBe(true)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('still reports a missing session and a token-only server as signed out', async () => {
    fetchSpy.mockResolvedValueOnce(respond(200, { authenticated: false }))
    fetchSpy.mockResolvedValueOnce(respond(404, { error: 'not found' }))

    await expect(discoverSession()).resolves.toEqual({ authenticated: false, csrfToken: '' })
    await expect(discoverSession()).resolves.toEqual({ authenticated: false, csrfToken: '' })
  })
})
