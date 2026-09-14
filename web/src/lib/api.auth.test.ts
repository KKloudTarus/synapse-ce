import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, discoverSession, logoutSession, setCSRFToken, setToken, setUnauthorizedHandler } from './api'

describe('BFF session API helpers', () => {
  const fetchSpy = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchSpy)
    fetchSpy.mockReset()
    setToken('')
    setCSRFToken('')
    setUnauthorizedHandler(() => {})
  })

  it('discovers sessions outside the v1 prefix with same-origin credentials', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ authenticated: true, csrf_token: 'csrf-1' }) } as Response)

    await expect(discoverSession()).resolves.toEqual({ authenticated: true, csrfToken: 'csrf-1' })
    expect(fetchSpy).toHaveBeenCalledWith('/api/auth/session', { credentials: 'same-origin' })
  })

  it('treats explicitly invalid sessions as unauthenticated', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({ error: 'authentication failed', code: 'authentication_invalid', request_id: 'r1', retryable: false }),
    } as Response)

    await expect(discoverSession()).resolves.toEqual({ authenticated: false, csrfToken: '' })
  })

  it('keeps rolling-upgrade compatibility for legacy status-only 401 session responses', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ error: 'unauthorized' }) } as Response)

    await expect(discoverSession()).resolves.toEqual({ authenticated: false, csrfToken: '' })
  })

  it('preserves a browser credential when session discovery hits a dependency outage', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({ error: 'identity service temporarily unavailable', code: 'dependency_unavailable', request_id: 'req-42', retryable: true }),
    } as Response)

    const promise = discoverSession()
    await expect(promise).rejects.toMatchObject({
      status: 503,
      code: 'dependency_unavailable',
      requestId: 'req-42',
      retryable: true,
    })
  })

  it('does not reinterpret an unknown future identity code as invalid authentication', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({ error: 'future identity state', code: 'future_identity_state', request_id: 'r2', retryable: false }),
    } as Response)

    await expect(discoverSession()).rejects.toMatchObject({ status: 401, code: 'future_identity_state' })
  })

  it('sends the in-memory CSRF token for unsafe session requests and logout', async () => {
    setCSRFToken('csrf-1')
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) } as Response)
    await logoutSession()
    expect(fetchSpy.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', headers: { 'X-CSRF-Token': 'csrf-1' } })

    fetchSpy.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ id: 'p1' }) } as Response)
    await api.createProject({ name: 'Project', key: 'project', sourceBinding: { kind: 'local', value: '/repo', ref: '' } })
    expect(fetchSpy.mock.calls[1][1]).toMatchObject({ credentials: 'same-origin', headers: { 'X-CSRF-Token': 'csrf-1' } })
  })

  it('preserves bearer authentication without cookies or the CSRF header', async () => {
    setCSRFToken('csrf-1')
    setToken('api-token')
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ id: 'p1' }) } as Response)

    await api.createProject({ name: 'Project', key: 'project', sourceBinding: { kind: 'local', value: '/repo', ref: '' } })
    expect(fetchSpy.mock.calls[0][1]).toMatchObject({ credentials: 'omit', headers: { authorization: 'Bearer api-token' } })
    expect((fetchSpy.mock.calls[0][1] as RequestInit).headers).not.toHaveProperty('X-CSRF-Token')
  })

  it('preserves bearer state on dependency failure and notifies only for authentication_invalid', async () => {
    const unauthorized = vi.fn()
    setUnauthorizedHandler(unauthorized)
    setToken('saved-token')

    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({ error: 'identity service temporarily unavailable', code: 'dependency_unavailable', retryable: true }),
    } as Response)
    await expect(api.aup()).rejects.toMatchObject({ code: 'dependency_unavailable', retryable: true })
    expect(unauthorized).not.toHaveBeenCalled()

    // Prove the credential was preserved through externally observable request behavior rather than
    // exposing the client's private token getter through the public API barrel solely for a test.
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ accepted: true }) } as Response)
    await api.aup()
    expect(fetchSpy.mock.calls[1][1]).toMatchObject({ credentials: 'omit', headers: { authorization: 'Bearer saved-token' } })

    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({ error: 'authentication failed', code: 'authentication_invalid', retryable: false }),
    } as Response)
    await expect(api.aup()).rejects.toMatchObject({ code: 'authentication_invalid' })
    expect(unauthorized).toHaveBeenCalledTimes(1)
  })

  it('keeps legacy 401 bearer behavior during rolling upgrade', async () => {
    const unauthorized = vi.fn()
    setUnauthorizedHandler(unauthorized)
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ error: 'unauthorized' }) } as Response)

    await expect(api.aup()).rejects.toBeInstanceOf(ApiError)
    expect(unauthorized).toHaveBeenCalledTimes(1)
  })

  it('rejects an authenticated session that has no usable CSRF token', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ authenticated: true }) } as Response)

    await expect(discoverSession()).rejects.toThrow(/CSRF token/)
  })
})
