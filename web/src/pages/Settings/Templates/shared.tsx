import { Lock01 } from '@untitledui/icons'
import { useCallback, useEffect, useState } from 'react'
import { BadgeWithDot } from '../../../components/base/badges/badges'
import { EmptyState } from '../../../components/ui'
import { api, ApiError, type NotificationEventSpec, type NotificationTemplateFamily, type NotificationTemplateStatus } from '../../../lib/api'
import type { NotificationEventVariable } from '../../../lib/api/notifications'
import { capabilityHint, disabledCapability, loadCapabilities } from '../../../lib/capabilities'
import { canManageIntegrations } from '../../../lib/roles'

export const ANY_EVENT = '*'

export const FAMILY_LABEL: Record<NotificationTemplateFamily, string> = {
  chat: 'Chat',
  email: 'Email',
  pager: 'Pager',
  ticket: 'Ticket',
  webhook: 'Webhook',
}

export const FAMILY_INFO: Record<NotificationTemplateFamily, string> = {
  chat: 'Slack, Microsoft Teams, Google Chat, Discord and Telegram channels.',
  email: 'Email channels.',
  pager: 'Paging services such as PagerDuty and Opsgenie.',
  ticket: 'Ticketing systems such as Jira.',
  webhook: 'Generic webhook channels.',
}

export const FIELD_LABEL: Record<string, string> = {
  title: 'Title',
  body: 'Body',
  subject: 'Subject',
  summary: 'Summary',
  description: 'Description',
}

export const LOCALE_LABEL: Record<string, string> = {
  en: 'English',
  vi: 'Vietnamese',
  '*': 'Any language (*)',
}

const STATUS_BADGE: Record<NotificationTemplateStatus, { label: string; color: 'gray' | 'success' | 'warning' }> = {
  draft: { label: 'Draft', color: 'warning' },
  active: { label: 'Active', color: 'success' },
  archived: { label: 'Archived', color: 'gray' },
}

export function StatusBadge({ status }: { status: NotificationTemplateStatus }) {
  const badge = STATUS_BADGE[status] ?? STATUS_BADGE.draft
  return (
    <BadgeWithDot type="pill-color" size="sm" color={badge.color}>
      {badge.label}
    </BadgeWithDot>
  )
}

export function eventLabel(catalog: NotificationEventSpec[], type: string): string {
  if (type === ANY_EVENT) return 'Any event (*)'
  return catalog.find((spec) => spec.type === type)?.label ?? type
}

/**
 * The variables a template for `eventType` may use. A `*` template is compiled against every
 * catalog event, so it may only use a variable every event declares (by name).
 */
export function templateVariables(catalog: NotificationEventSpec[], eventType: string): NotificationEventVariable[] {
  if (eventType !== ANY_EVENT) return catalog.find((spec) => spec.type === eventType)?.variables ?? []
  if (catalog.length === 0) return []
  const [first, ...rest] = catalog
  return (first.variables ?? []).filter((variable) =>
    rest.every((spec) => (spec.variables ?? []).some((other) => other.name === variable.name)),
  )
}

export function formatDateTime(value: string | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export type TemplateAccess =
  | { state: 'loading' }
  | { state: 'error'; message: string; retry: () => void }
  | { state: 'denied' }
  | { state: 'off'; hint: string }
  | { state: 'ready' }

/**
 * Decides whether the signed-in user may work with templates. Every template route needs
 * `manage_integrations` (admin and integration_admin), and the routes exist only while the
 * notifications framework is on; checking both first keeps the page from calling routes that
 * would answer 403 or 404.
 */
export function useTemplateAccess(): TemplateAccess {
  const [access, setAccess] = useState<TemplateAccess>({ state: 'loading' })
  const [generation, setGeneration] = useState(0)
  const retry = useCallback(() => setGeneration((value) => value + 1), [])

  useEffect(() => {
    let live = true
    setAccess({ state: 'loading' })
    Promise.all([api.me(), loadCapabilities()])
      .then(([me, capabilities]) => {
        if (!live) return
        if (!canManageIntegrations(me?.role)) return setAccess({ state: 'denied' })
        const off = disabledCapability(capabilities, 'notifications')
        setAccess(off ? { state: 'off', hint: capabilityHint(off) } : { state: 'ready' })
      })
      .catch((caught) => {
        if (live) setAccess({ state: 'error', message: errorMessage(caught), retry })
      })
    return () => {
      live = false
    }
  }, [generation, retry])

  return access
}

export function PermissionDenied() {
  return (
    <EmptyState
      icon={Lock01}
      title="Administrator access required"
      hint="Only tenant administrators and integration administrators can view and edit message templates."
    />
  )
}

export function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403
}
