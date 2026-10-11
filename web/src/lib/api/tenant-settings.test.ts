import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { tenantSettingsApi } from './tenant-settings'

describe('tenant settings API', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch')
  })
  afterEach(() => vi.restoreAllMocks())
  function respond(body: unknown, status = 200) {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as Response)
  }

  it('maps the wire shape, including the defaults at revision 0', async () => {
    respond({ default_locale: 'en', time_zone: 'UTC', revision: 0, locales: ['en', 'vi'] })
    expect(await tenantSettingsApi.getTenantSettings()).toEqual({
      defaultLocale: 'en',
      timeZone: 'UTC',
      revision: 0,
      updatedAt: undefined,
      locales: ['en', 'vi'],
    })
    expect(fetch).toHaveBeenCalledWith('/api/v1/tenant/settings', expect.any(Object))
  })

  it('sends only the settings and the revision, never a tenant', async () => {
    respond({ default_locale: 'vi', time_zone: 'Asia/Ho_Chi_Minh', revision: 1, updated_at: '2026-09-28T08:00:00Z', locales: ['en', 'vi'] })
    const saved = await tenantSettingsApi.saveTenantSettings({ defaultLocale: 'vi', timeZone: 'Asia/Ho_Chi_Minh', revision: 0 })
    const [url, options] = vi.mocked(fetch).mock.calls[0]
    expect(url).toBe('/api/v1/tenant/settings')
    expect(options?.method).toBe('PUT')
    expect(JSON.parse(String(options?.body))).toEqual({ default_locale: 'vi', time_zone: 'Asia/Ho_Chi_Minh', revision: 0 })
    expect(saved.revision).toBe(1)
    expect(saved.updatedAt).toBe('2026-09-28T08:00:00Z')
  })
})
