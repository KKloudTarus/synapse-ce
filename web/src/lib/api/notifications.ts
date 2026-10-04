import { req } from './client'
// One definition, shared with the template API client (#1373).
import type { NotificationTemplateFamily } from './notification-templates'

export type NotificationChannelType =
  | 'webhook'
  | 'slack'
  | 'email'
  | 'teams'
  | 'telegram'
  | 'google_chat'
  | 'discord'
// The server's event catalog is the source of truth for event types, so the console accepts any
// type it declares instead of a hard-coded union.
export type NotificationEventType = string
export type NotificationRuleFilter =
  | 'min_severity'
  | 'action_types'
  | 'engagement_ids'
  | 'team_ids'
  | 'lead_time_seconds'
export type NotificationDataClass = 'signal' | 'summary' | 'detail'
export type NotificationLocale = 'en' | 'vi'
/** A template a channel can bind: the head fields of the template API (#1370). */
export interface NotificationTemplateOption {
  id: string
  name: string
  event_type: string
  family: NotificationTemplateFamily
  locale: NotificationLocale | '*'
  status: 'draft' | 'active' | 'archived'
  active_version: number
}
export type NotificationResolutionTier =
  | 'channel'
  | 'tenant_event'
  | 'tenant_wildcard'
  | 'builtin'
  | 'fallback'
/** Which template a channel renders an event type with (#1371). Never carries template source. */
export interface NotificationTemplateResolution {
  tier: NotificationResolutionTier
  event_type: string
  family?: NotificationTemplateFamily
  locale: NotificationLocale
  locale_source: 'channel' | 'tenant' | 'default'
  matched_locale?: NotificationLocale | '*'
  template?: NotificationTemplateOption
  version?: number
  builtin_ref?: string
  binding_skipped?:
    | 'template_not_active'
    | 'event_not_covered'
    | 'locale_not_covered'
    | 'family_mismatch'
    | 'template_missing'
}
export interface NotificationEventVariable {
  name: string
  class: NotificationDataClass
  description: string
  list_cap: number
}
export interface NotificationEventSpec {
  type: NotificationEventType
  label: string
  schema_version: number
  subject_kind: string
  has_engagement: boolean
  has_severity: boolean
  has_team: boolean
  has_lead_time: boolean
  filters: NotificationRuleFilter[]
  max_data_class: NotificationDataClass
  mandatory: boolean
  operator_only: boolean
  variables: NotificationEventVariable[]
}
export type NotificationDeliveryState =
  | 'pending'
  | 'retrying'
  | 'delivered'
  | 'dead_letter'
  | 'cancelled'

/**
 * Delivery health the worker keeps on a channel (#1464). A channel pauses after consecutive
 * permanent failures; only an administrator resumes it. Codes are bounded identifiers, never a URL.
 */
export interface NotificationChannelHealth {
  state: 'active' | 'paused'
  paused_at?: string
  paused_reason?: string
  consecutive_failures: number
  last_failure_code?: string
  last_failure_at?: string
}
export interface NotificationChannelHealthEvent {
  id: string
  channel_id: string
  action: 'paused' | 'resumed'
  reason?: string
  failure_code?: string
  failures: number
  delivery_id?: string
  attempt_id?: string
  actor: string
  occurred_at: string
}
export interface NotificationChannel {
  id: string
  name: string
  type: NotificationChannelType
  enabled: boolean
  destination: string
  recipients?: string[]
  revision: number
  secret_version: number
  created_at: string
  updated_at: string
  /** Absent only from a server that predates channel health. */
  health?: NotificationChannelHealth
  /** The bound template of the channel family (#1371); absent when none is bound. */
  template_id?: string
  /** The channel locale; absent when the tenant default applies. */
  locale?: NotificationLocale
  /** A webhook channel sends its template body as a custom JSON body (#1376). */
  custom_body?: boolean
}
export interface NotificationChannelInput {
  name: string
  type: NotificationChannelType
  enabled: boolean
  url?: string
  secret?: string
  recipients?: string[]
  /** Telegram only: a numeric chat ID or an @channel username. The bot token goes in `secret`. */
  chat_id?: string
  /** Telegram only: the forum topic to post into; omitted posts to the main chat. */
  thread_id?: number
  revision?: number
  /** Omitted keeps the binding; an empty string unbinds. */
  template_id?: string
  /** Omitted keeps the locale; an empty string uses the tenant default. */
  locale?: NotificationLocale | ''
  /** Webhook only; needs a bound template. Omitted keeps the current value. */
  custom_body?: boolean
}
export interface NotificationRule {
  id: string
  name: string
  enabled: boolean
  event_type: NotificationEventType
  min_severity?: string
  action_types?: string[]
  engagement_ids?: string[]
  team_ids?: string[]
  all_teams?: boolean
  channel_ids: string[]
  lead_time_seconds?: number
  revision: number
  created_at: string
  updated_at: string
}
export type NotificationRuleInput = Omit<
  NotificationRule,
  'id' | 'created_at' | 'updated_at'
>
export interface NotificationDelivery {
  id: string
  event_id: string
  channel_id: string
  channel_type: NotificationChannelType
  redrive_fence: number
  recipient?: string
  matched_rule_ids: string[]
  state: NotificationDeliveryState
  attempts: number
  last_error?: string
  next_attempt_at?: string
  delivered_at?: string
  created_at: string
  updated_at: string
}
export interface NotificationAttempt {
  id: string
  delivery_id: string
  number: number
  started_at: string
  finished_at?: string
  outcome: string
  response_code?: number
  error_code?: string
}

export interface NotificationDeliveryQuery {
  channel_id?: string
  event_type?: string
  state?: string
  cursor?: string
  from?: string
  to?: string
}
export interface NotificationDeliveryPage {
  items: NotificationDelivery[]
  next?: string
}

export interface NotificationSourceFailure {
  source_kind: string
  source_id: string
  event_type: string
  occurred_at: string
  processed_at: string
  failed_reason: 'invalid_event' | 'event_data_too_large'
}
export interface NotificationSourceFailurePage {
  items: NotificationSourceFailure[]
  next_offset?: number
}

export const notificationsApi = {
  listNotificationEventTypes: async (): Promise<NotificationEventSpec[]> =>
    ((await req('/notifications/event-types')) as {
      items?: NotificationEventSpec[]
    }).items ?? [],
  // Whether the framework is on comes from the `notifications` capability, not from a 404 here.
  listNotificationChannels: async (): Promise<NotificationChannel[]> =>
    ((await req('/notifications/channels')) as { items?: NotificationChannel[] })
      .items ?? [],
  createNotificationChannel: (
    input: NotificationChannelInput,
  ): Promise<NotificationChannel> =>
    req('/notifications/channels', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  updateNotificationChannel: (
    id: string,
    input: NotificationChannelInput,
  ): Promise<NotificationChannel> =>
    req(`/notifications/channels/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    }),
  deleteNotificationChannel: (id: string, revision: number): Promise<void> =>
    req(
      `/notifications/channels/${encodeURIComponent(id)}?revision=${revision}`,
      { method: 'DELETE' },
    ),
  testNotificationChannel: (
    id: string,
  ): Promise<{ delivery_id: string; state: 'pending' }> =>
    req(`/notifications/channels/${encodeURIComponent(id)}/test`, {
      method: 'POST',
    }),
  // Resume sends only the revision the administrator saw; the server refuses a stale one.
  resumeNotificationChannel: (
    id: string,
    revision: number,
  ): Promise<NotificationChannel> =>
    req(`/notifications/channels/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ revision }),
    }),
  listNotificationChannelHealthEvents: async (
    id: string,
  ): Promise<NotificationChannelHealthEvent[]> =>
    (
      (await req(
        `/notifications/channels/${encodeURIComponent(id)}/health-events`,
      )) as { items?: NotificationChannelHealthEvent[] }
    ).items ?? [],
  // Active templates of one family, for the channel form's template select (#1371).
  listBindableNotificationTemplates: async (
    family: NotificationTemplateFamily,
  ): Promise<NotificationTemplateOption[]> =>
    (
      (await req(
        `/notifications/templates?family=${encodeURIComponent(family)}&status=active`,
      )) as { items?: NotificationTemplateOption[] }
    ).items ?? [],
  previewNotificationTemplateResolution: (
    channelId: string,
    eventType: string,
  ): Promise<NotificationTemplateResolution> =>
    req(
      `/notifications/channels/${encodeURIComponent(channelId)}/template-resolution?event_type=${encodeURIComponent(eventType)}`,
    ),
  listNotificationRules: async (): Promise<NotificationRule[]> =>
    ((await req('/notifications/rules')) as { items?: NotificationRule[] })
      .items ?? [],
  createNotificationRule: (
    input: Omit<NotificationRuleInput, 'revision'>,
  ): Promise<NotificationRule> =>
    req('/notifications/rules', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  updateNotificationRule: (
    id: string,
    input: NotificationRuleInput,
  ): Promise<NotificationRule> =>
    req(`/notifications/rules/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name: input.name,
        enabled: input.enabled,
        event_type: input.event_type,
        min_severity: input.min_severity,
        action_types: input.action_types,
        engagement_ids: input.engagement_ids,
        // PATCH replaces the whole rule, so an ownership rule must resend its team scope.
        team_ids: input.team_ids,
        all_teams: input.all_teams,
        channel_ids: input.channel_ids,
        lead_time_seconds: input.lead_time_seconds,
        revision: input.revision,
      }),
    }),
  deleteNotificationRule: (id: string, revision: number): Promise<void> =>
    req(`/notifications/rules/${encodeURIComponent(id)}?revision=${revision}`, {
      method: 'DELETE',
    }),
  listNotificationDeliveries: async (): Promise<NotificationDelivery[]> =>
    (
      (await req('/notifications/deliveries?limit=100')) as {
        items?: NotificationDelivery[]
      }
    ).items ?? [],
  listNotificationAttempts: async (
    id: string,
  ): Promise<NotificationAttempt[]> =>
    (await req(`/notifications/deliveries/${encodeURIComponent(id)}/attempts`))
      .items ?? [],
  redriveNotificationDelivery: (
    id: string,
    reason: string,
    expectedFence: number,
  ): Promise<NotificationDelivery> =>
    req(`/notifications/deliveries/${encodeURIComponent(id)}/redrive`, {
      method: 'POST',
      body: JSON.stringify({ reason, expected_fence: expectedFence }),
    }),
  notificationDeliveryPage: async (
    query: NotificationDeliveryQuery = {},
  ): Promise<NotificationDeliveryPage> => {
    const params = new URLSearchParams({ limit: '50' })
    for (const [key, value] of Object.entries(query))
      if (value) params.set(key, value)
    return req('/notifications/deliveries?' + params.toString())
  },
  notificationSourceFailurePage: async (query: {
    event_type?: string
    from?: string
    to?: string
    offset?: number
  } = {}): Promise<NotificationSourceFailurePage> => {
    const params = new URLSearchParams({ limit: '50' })
    for (const [key, value] of Object.entries(query))
      if (value !== undefined && value !== '') params.set(key, String(value))
    return req('/notifications/quarantined-sources?' + params.toString())
  },
}
