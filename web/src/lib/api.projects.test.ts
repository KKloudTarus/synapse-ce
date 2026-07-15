import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

describe('Projects API', () => {
  let fetchSpy: any

  beforeEach(() => { fetchSpy = vi.spyOn(globalThis, 'fetch') })

  it('maps project fields', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => [{ ID: 'p1', Name: 'Synapse', Key: 'synapse', SourceBinding: { Kind: 'git', Value: 'https://example.com/repo.git', Ref: 'main' }, DefaultProfileByLang: { go: 'default' }, GateID: 'gate', Audit: { CreatedAt: '2026-07-15T00:00:00Z' } }] } as Response)
    const projects = await api.listProjects()
    expect(projects[0]).toMatchObject({ id: 'p1', key: 'synapse', gateId: 'gate', sourceBinding: { kind: 'git', ref: 'main' } })
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/projects', expect.any(Object))
  })

  it('creates with the backend source contract', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ ID: 'p1', Key: 'synapse', SourceBinding: { Kind: 'local', Value: '/repo' } }) } as Response)
    await api.createProject({ name: 'Synapse', key: 'synapse', sourceBinding: { kind: 'local', value: '/repo', ref: '' } })
    const init = fetchSpy.mock.calls[0][1] as RequestInit
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/projects')
    expect(JSON.parse(String(init.body))).toEqual({ name: 'Synapse', key: 'synapse', source_binding: { Kind: 'local', Value: '/repo', Ref: '' } })
  })

  it('encodes project keys', async () => {
    fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ Key: 'a b' }) } as Response)
    await api.getProject('a b')
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/projects/a%20b', expect.any(Object))
  })
})
