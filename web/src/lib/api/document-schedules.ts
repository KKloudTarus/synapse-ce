import { req } from './client'
import type { DocumentSourceKind } from './documents'

export type DocumentScheduleScope = 'engagement' | 'project'
export type DocumentScheduleDestination = 'confluence' | 'email'
export type DocumentScheduleFrequency = 'weekly' | 'monthly'

export interface DocumentSchedule {
  id: string
  sourceKind: DocumentSourceKind
  sourceRef: string
  scope: DocumentScheduleScope
  scopeId: string
  destination: DocumentScheduleDestination
  integrationId?: string
  emailChannelId?: string
  timezone: string
  frequency: DocumentScheduleFrequency
  weekday: number
  day: number
  hour: number
  minute: number
  enabled: boolean
  version: number
  nextDueAt: string
  updatedAt: string
}

export interface DocumentScheduleEmailDestination {
  id: string
  name: string
  recipientCount: number
}

export interface DocumentScheduleRun {
  id: string
  dueAt: string
  state: 'pending' | 'in_flight' | 'done' | 'uncertain' | 'failed' | string
  contentHash?: string
  remotePageId?: string
  remoteVersion: number
  deliveredCount: number
  uncertainCount: number
  failedCount: number
  updatedAt: string
}

export interface DocumentScheduleInput {
  sourceKind: DocumentSourceKind
  sourceRef: string
  scopeId: string
  destination: DocumentScheduleDestination
  integrationId?: string
  emailChannelId?: string
  timezone: string
  frequency: DocumentScheduleFrequency
  weekday?: number
  day?: number
  hour: number
  minute: number
  enabled: boolean
  expectedVersion?: number
}

const schedule = (value: any): DocumentSchedule => ({
  id: value?.id ?? '', sourceKind: value?.source_kind ?? 'engagement_report', sourceRef: value?.source_ref ?? '', scope: value?.scope === 'project' ? 'project' : 'engagement', scopeId: value?.scope_id ?? '', destination: value?.destination === 'email' ? 'email' : 'confluence', integrationId: value?.integration_id || undefined, emailChannelId: value?.email_channel_id || undefined, timezone: value?.timezone ?? '', frequency: value?.frequency === 'monthly' ? 'monthly' : 'weekly', weekday: Number(value?.weekday ?? 0), day: Number(value?.day ?? 0), hour: Number(value?.hour ?? 0), minute: Number(value?.minute ?? 0), enabled: value?.enabled === true, version: Number(value?.version ?? 0), nextDueAt: value?.next_due_at ?? '', updatedAt: value?.updated_at ?? '',
})

const payload = (input: DocumentScheduleInput) => ({
  source_kind: input.sourceKind, source_ref: input.sourceRef, scope_id: input.scopeId, destination: input.destination,
  integration_id: input.integrationId ?? '', email_channel_id: input.emailChannelId ?? '', timezone: input.timezone,
  frequency: input.frequency, weekday: input.weekday ?? 0, day: input.day ?? 0, hour: input.hour, minute: input.minute,
  enabled: input.enabled, expected_version: input.expectedVersion ?? 0,
})

const run = (value: any): DocumentScheduleRun => ({
  id: value?.id ?? '', dueAt: value?.due_at ?? '', state: value?.state ?? '', contentHash: value?.content_hash || undefined,
  remotePageId: value?.remote_page_id || undefined, remoteVersion: Number(value?.remote_version ?? 0), deliveredCount: Number(value?.delivered_count ?? 0), uncertainCount: Number(value?.uncertain_count ?? 0), failedCount: Number(value?.failed_count ?? 0), updatedAt: value?.updated_at ?? '',
})

export const documentSchedulesApi = {
  list: async (scope: DocumentScheduleScope, scopeId: string): Promise<DocumentSchedule[]> =>
    ((await req(`/document-schedules?scope=${encodeURIComponent(scope)}&scope_id=${encodeURIComponent(scopeId)}`)) ?? []).map(schedule),
  save: async (input: DocumentScheduleInput): Promise<DocumentSchedule> => schedule(await req('/document-schedules', { method: 'POST', body: JSON.stringify(payload(input)) })),
  disable: async (id: string, expectedVersion: number): Promise<void> => {
    await req(`/document-schedules/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ expected_version: expectedVersion }) })
  },
  runs: async (scheduleID: string): Promise<DocumentScheduleRun[]> =>
    ((await req(`/document-schedules/${encodeURIComponent(scheduleID)}/runs`)) ?? []).map(run),
  emailDestinations: async (): Promise<DocumentScheduleEmailDestination[]> =>
    ((await req('/document-schedules/email-destinations')) ?? []).map((value: any) => ({ id: value?.id ?? '', name: value?.name ?? '', recipientCount: Number(value?.recipient_count ?? 0) })),
}
