import { ApiError, req } from './client'

export type NotificationChannelType = 'webhook' | 'slack' | 'email'
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
}
export interface NotificationChannelInput {
  name: string
  type: NotificationChannelType
  enabled: boolean
  url?: string
  secret?: string
  recipients?: string[]
  revision?: number
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

async function optional<T>(path: string): Promise<T | null> {
  try {
    return await req(path)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
}

export const notificationsApi = {
  listNotificationEventTypes: async (): Promise<NotificationEventSpec[]> =>
    ((await req('/notifications/event-types')) as {
      items?: NotificationEventSpec[]
    }).items ?? [],
  listNotificationChannels: async (): Promise<NotificationChannel[] | null> =>
    (
      await optional<{ items: NotificationChannel[] }>(
        '/notifications/channels',
      )
    )?.items ?? null,
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
  listNotificationRules: async (): Promise<NotificationRule[] | null> =>
    (await optional<{ items: NotificationRule[] }>('/notifications/rules'))
      ?.items ?? null,
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
        channel_ids: input.channel_ids,
        lead_time_seconds: input.lead_time_seconds,
        revision: input.revision,
      }),
    }),
  deleteNotificationRule: (id: string, revision: number): Promise<void> =>
    req(`/notifications/rules/${encodeURIComponent(id)}?revision=${revision}`, {
      method: 'DELETE',
    }),
  listNotificationDeliveries: async (): Promise<
    NotificationDelivery[] | null
  > =>
    (
      await optional<{ items: NotificationDelivery[] }>(
        '/notifications/deliveries?limit=100',
      )
    )?.items ?? null,
  listNotificationAttempts: async (
    id: string,
  ): Promise<NotificationAttempt[]> =>
    (await req(`/notifications/deliveries/${encodeURIComponent(id)}/attempts`))
      .items ?? [],
  notificationDeliveryPage: async (
    query: NotificationDeliveryQuery = {},
  ): Promise<NotificationDeliveryPage> => {
    const params = new URLSearchParams({ limit: '50' })
    for (const [key, value] of Object.entries(query))
      if (value) params.set(key, value)
    return req('/notifications/deliveries?' + params.toString())
  },
}
