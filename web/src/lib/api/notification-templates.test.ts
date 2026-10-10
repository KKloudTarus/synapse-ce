import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './client'
import { notificationTemplatesApi, templateValidationError } from './notification-templates'
import { formatValidation } from '../../pages/Settings/Templates/TemplateEditor'

describe('notification template API', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch')
  })
  afterEach(() => vi.restoreAllMocks())
  function respond(body: unknown, status = 200) {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as Response)
  }

  it('sends the filters and follows full pages with after', async () => {
    const page = Array.from({ length: 500 }, (_, index) => ({ id: `t${String(index).padStart(3, '0')}` }))
    respond({ items: page })
    respond({ items: [{ id: 'last' }] })
    const items = await notificationTemplatesApi.listNotificationTemplates({ event_type: '*', family: 'chat', status: 'draft' })
    expect(items).toHaveLength(501)
    const first = new URL(String(vi.mocked(fetch).mock.calls[0][0]), 'http://x')
    expect(first.pathname).toBe('/api/v1/notifications/templates')
    expect(Object.fromEntries(first.searchParams)).toEqual({ event_type: '*', family: 'chat', status: 'draft', limit: '500' })
    const second = new URL(String(vi.mocked(fetch).mock.calls[1][0]), 'http://x')
    expect(second.searchParams.get('after')).toBe('t499')
  })

  it('posts activate, rollback and archive with the revision', async () => {
    respond({ id: 'a/b' })
    await notificationTemplatesApi.rollbackNotificationTemplate('a/b', { revision: 4, version: 1 })
    const [url, options] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toContain('/notifications/templates/a%2Fb/rollback')
    expect(options).toMatchObject({ method: 'POST', body: JSON.stringify({ revision: 4, version: 1 }) })
  })

  it('lists the shipped built-ins from the read-only catalog endpoint', async () => {
    respond({ items: [{ event_type: 'scan.completed', family: 'chat', locale: 'vi', fields: { title: 'Quét xong', body: 'Xem Synapse' } }] })
    await expect(notificationTemplatesApi.listBuiltinNotificationTemplates()).resolves.toEqual([
      { event_type: 'scan.completed', family: 'chat', locale: 'vi', fields: { title: 'Quét xong', body: 'Xem Synapse' } },
    ])
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toContain('/api/v1/notifications/templates/builtins')
  })

  it('treats only a missing catalog route as an older server with no built-ins', async () => {
    respond({ error: 'not found' }, 404)
    await expect(notificationTemplatesApi.listBuiltinNotificationTemplates()).resolves.toEqual([])

    respond({ error: 'unavailable' }, 503)
    await expect(notificationTemplatesApi.listBuiltinNotificationTemplates()).rejects.toMatchObject({ status: 503 })
  })

  it('reads the structured body of an engine rejection', () => {
    const error = new ApiError(400, 'bad', { error: 'bad', field: 'body', event_type: '*', code: 'parse_error', line: 3 })
    expect(templateValidationError(error)).toEqual({ error: 'bad', field: 'body', event_type: '*', code: 'parse_error', line: 3 })
    expect(templateValidationError(new ApiError(400, 'plain', { error: 'plain' }))).toEqual({
      error: 'plain', field: undefined, event_type: undefined, code: undefined, line: undefined,
    })
    expect(templateValidationError(new ApiError(409, 'stale'))).toBeNull()
  })

  it('keeps the JSON path of a custom webhook body rejection (#1376)', () => {
    const error = new ApiError(400, 'bad', {
      error: 'template expressions are allowed only inside string values', field: 'body', code: 'expression_outside_string', path: '$.a["k"]',
    })
    expect(templateValidationError(error)?.path).toBe('$.a["k"]')
    expect(formatValidation({ error: 'x', code: 'expression_outside_string', path: '$.a["k"]' })).toBe('$.a["k"] · expression_outside_string: x')
  })

  it('reads one version as the single version below it, and 404s a gap', async () => {
    respond({ items: [{ version: 7 }] })
    expect(await notificationTemplatesApi.getNotificationTemplateVersion('a/b', 7)).toEqual({ version: 7 })
    const url = new URL(String(vi.mocked(fetch).mock.calls[0][0]), 'http://x')
    expect(url.pathname).toBe('/api/v1/notifications/templates/a%2Fb/versions')
    expect(Object.fromEntries(url.searchParams)).toEqual({ limit: '1', before: '8' })
    respond({ items: [{ version: 5 }] })
    await expect(notificationTemplatesApi.getNotificationTemplateVersion('a', 7)).rejects.toMatchObject({ status: 404 })
  })
})
