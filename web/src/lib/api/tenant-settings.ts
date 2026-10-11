import { req } from './client'

/**
 * Tenant language and time zone (#1359). Wire shape: `tenantSettingsView` in
 * internal/adapter/httpapi/tenant_settings_handler.go. Message templates and digests render in
 * these; a tenant that never saved them reads the defaults at revision 0.
 */
export type TenantLocale = 'en' | 'vi'

export interface TenantSettings {
  defaultLocale: TenantLocale
  timeZone: string
  revision: number
  updatedAt?: string
  /** Every language this build renders, in display order. */
  locales: TenantLocale[]
}

export interface TenantSettingsInput {
  defaultLocale: TenantLocale
  timeZone: string
  /** The revision the caller read; 0 for a tenant's first save. */
  revision: number
}

function mapTenantSettings(raw: any): TenantSettings {
  return {
    defaultLocale: raw?.default_locale === 'vi' ? 'vi' : 'en',
    timeZone: typeof raw?.time_zone === 'string' && raw.time_zone ? raw.time_zone : 'UTC',
    revision: typeof raw?.revision === 'number' ? raw.revision : 0,
    updatedAt: typeof raw?.updated_at === 'string' ? raw.updated_at : undefined,
    locales: Array.isArray(raw?.locales) && raw.locales.length > 0 ? raw.locales : ['en', 'vi'],
  }
}

export const tenantSettingsApi = {
  getTenantSettings: async (): Promise<TenantSettings> => mapTenantSettings(await req('/tenant/settings')),
  saveTenantSettings: async (input: TenantSettingsInput): Promise<TenantSettings> =>
    mapTenantSettings(
      await req('/tenant/settings', {
        method: 'PUT',
        body: JSON.stringify({
          default_locale: input.defaultLocale,
          time_zone: input.timeZone,
          revision: input.revision,
        }),
      }),
    ),
}
