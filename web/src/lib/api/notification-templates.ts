import { ApiError, req } from './client'

/**
 * Client for the custom notification template API (#1370). Every route needs
 * `manage_integrations`; the server answers 403 otherwise.
 */

export type NotificationTemplateFamily = 'chat' | 'email' | 'pager' | 'ticket' | 'webhook'
export type NotificationTemplateStatus = 'draft' | 'active' | 'archived'
export type NotificationTemplateLocale = 'en' | 'vi' | '*'

export const TEMPLATE_FAMILIES: NotificationTemplateFamily[] = ['chat', 'email', 'pager', 'ticket', 'webhook']
export const TEMPLATE_LOCALES: NotificationTemplateLocale[] = ['en', 'vi', '*']
export const TEMPLATE_STATUSES: NotificationTemplateStatus[] = ['draft', 'active', 'archived']

/** Content fields each family renders, in display order (internal/domain/notification/template.go). */
export const TEMPLATE_FAMILY_FIELDS: Record<NotificationTemplateFamily, string[]> = {
  chat: ['title', 'body'],
  email: ['subject', 'body'],
  pager: ['summary'],
  ticket: ['summary', 'description'],
  webhook: ['body'],
}

/** A field's source is capped at 16 KiB by the engine. */
export const TEMPLATE_FIELD_MAX_BYTES = 16384

export interface NotificationTemplate {
  tenant_id: string
  id: string
  name: string
  event_type: string
  family: NotificationTemplateFamily
  locale: NotificationTemplateLocale
  status: NotificationTemplateStatus
  latest_version: number
  /** 0 when the template was never activated. */
  active_version: number
  revision: number
  created_at: string
  created_by: string
  updated_at: string
  updated_by: string
}

export interface NotificationTemplateVersion {
  tenant_id: string
  template_id: string
  version: number
  fields: Record<string, string>
  checksum: string
  created_at: string
  created_by: string
}

export interface NotificationTemplateDetail extends NotificationTemplate {
  latest?: NotificationTemplateVersion
  active?: NotificationTemplateVersion
  archived_template_id?: string
}

export interface NotificationTemplateInput {
  name: string
  event_type: string
  family: NotificationTemplateFamily
  locale: NotificationTemplateLocale
  fields: Record<string, string>
}

export interface NotificationTemplateUpdateInput {
  name?: string
  fields: Record<string, string>
  revision: number
}

export interface NotificationTemplateQuery {
  event_type?: string
  family?: NotificationTemplateFamily
  locale?: NotificationTemplateLocale
  status?: NotificationTemplateStatus
}

/** The 400 body of a field the template engine rejected. It never repeats the template source. */
export interface NotificationTemplateValidationError {
  error: string
  field?: string
  event_type?: string
  code?: string
  line?: number
  /** JSON location of a custom webhook body error (#1376), e.g. `$.a["k"]`. */
  path?: string
}

/**
 * A built-in default template (#1366): read-only, one per (event type, family, locale). The console
 * can only clone it into a custom draft.
 */
export interface BuiltinNotificationTemplate {
  event_type: string
  family: NotificationTemplateFamily
  locale: NotificationTemplateLocale
  fields: Record<string, string>
}

/** Reads the structured validation body from a 400, or null for any other error. */
export function templateValidationError(error: unknown): NotificationTemplateValidationError | null {
  if (!(error instanceof ApiError) || error.status !== 400) return null
  const body = error.body as Partial<NotificationTemplateValidationError> | undefined
  return {
    error: typeof body?.error === 'string' ? body.error : error.message,
    field: typeof body?.field === 'string' && body.field !== '' ? body.field : undefined,
    event_type: typeof body?.event_type === 'string' && body.event_type !== '' ? body.event_type : undefined,
    code: typeof body?.code === 'string' && body.code !== '' ? body.code : undefined,
    line: typeof body?.line === 'number' && body.line > 0 ? body.line : undefined,
    path: typeof body?.path === 'string' && body.path !== '' ? body.path : undefined,
  }
}

/** The server's largest version page (ports.MaxNotificationTemplateVersionPage). */
export const TEMPLATE_VERSION_PAGE = 200

const PAGE_LIMIT = 500
// A tenant with more templates than this is not a realistic console case; the loop stops rather than
// paging forever against a server that keeps answering full pages.
const MAX_PAGES = 20

function templatePath(id: string, suffix = ''): string {
  return `/notifications/templates/${encodeURIComponent(id)}${suffix}`
}

export const notificationTemplatesApi = {
  /** Lists every template matching the filters, following `after` across full pages. */
  listNotificationTemplates: async (query: NotificationTemplateQuery = {}): Promise<NotificationTemplate[]> => {
    const all: NotificationTemplate[] = []
    let after = ''
    for (let page = 0; page < MAX_PAGES; page++) {
      const params = new URLSearchParams()
      if (query.event_type) params.set('event_type', query.event_type)
      if (query.family) params.set('family', query.family)
      if (query.locale) params.set('locale', query.locale)
      if (query.status) params.set('status', query.status)
      if (after) params.set('after', after)
      params.set('limit', String(PAGE_LIMIT))
      const items = ((await req(`/notifications/templates?${params}`)) as { items?: NotificationTemplate[] } | null)?.items ?? []
      all.push(...items)
      if (items.length < PAGE_LIMIT) break
      after = items[items.length - 1].id
    }
    return all
  },
  getNotificationTemplate: (id: string): Promise<NotificationTemplateDetail> => req(templatePath(id)),
  createNotificationTemplate: (input: NotificationTemplateInput): Promise<NotificationTemplateDetail> =>
    req('/notifications/templates', { method: 'POST', body: JSON.stringify(input) }),
  updateNotificationTemplate: (id: string, input: NotificationTemplateUpdateInput): Promise<NotificationTemplateDetail> =>
    req(templatePath(id), { method: 'PATCH', body: JSON.stringify(input) }),
  /** One page of versions, newest first; `before` pages to versions older than that number. */
  listNotificationTemplateVersions: async (id: string, before?: number, limit = TEMPLATE_VERSION_PAGE): Promise<NotificationTemplateVersion[]> => {
    const params = new URLSearchParams({ limit: String(limit) })
    if (before) params.set('before', String(before))
    return ((await req(`${templatePath(id, '/versions')}?${params}`)) as { items?: NotificationTemplateVersion[] } | null)?.items ?? []
  },
  /** One saved version, read as the single version just below `version + 1`. */
  getNotificationTemplateVersion: async (id: string, version: number): Promise<NotificationTemplateVersion> => {
    const [item] = await notificationTemplatesApi.listNotificationTemplateVersions(id, version + 1, 1)
    if (!item || item.version !== version) throw new ApiError(404, `version ${version} not found`)
    return item
  },
  activateNotificationTemplate: (id: string, input: { revision: number; version?: number }): Promise<NotificationTemplateDetail> =>
    req(templatePath(id, '/activate'), { method: 'POST', body: JSON.stringify(input) }),
  rollbackNotificationTemplate: (id: string, input: { revision: number; version: number }): Promise<NotificationTemplateDetail> =>
    req(templatePath(id, '/rollback'), { method: 'POST', body: JSON.stringify(input) }),
  archiveNotificationTemplate: (id: string, input: { revision: number }): Promise<NotificationTemplateDetail> =>
    req(templatePath(id, '/archive'), { method: 'POST', body: JSON.stringify({ revision: input.revision }) }),
  /** Built-in defaults; a 404 means the connected server predates this read-only route. */
  listBuiltinNotificationTemplates: async (): Promise<BuiltinNotificationTemplate[]> => {
    try {
      return ((await req('/notifications/templates/builtins')) as { items?: BuiltinNotificationTemplate[] } | null)?.items ?? []
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return []
      throw error
    }
  },
}
