import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, discoverSession, logoutSession, setCSRFToken, setToken } from './api'

describe('BFF session API helpers', () => {
  const fetchSpy = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchSpy)
    setToken('')
    setCSRFToken('')
  })

  it('discovers sessions outside the v1 prefix with same-origin credentials', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ authenticated: true, csrf_token: 'csrf-1' }) } as Response)

    await expect(discoverSession()).resolves.toEqual({ authenticated: true, csrfToken: 'csrf-1' })
    expect(fetchSpy).toHaveBeenCalledWith('/api/auth/session', { credentials: 'same-origin' })
  })

  it('treats expired sessions as unauthenticated', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({}) } as Response)

    await expect(discoverSession()).resolves.toEqual({ authenticated: false, csrfToken: '' })
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

  it('rejects an authenticated session that has no usable CSRF token', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ authenticated: true }) } as Response)

    await expect(discoverSession()).rejects.toThrow(/CSRF token/)
  })
})
