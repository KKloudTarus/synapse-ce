import { req } from './client'

const id = encodeURIComponent

export type DocumentSourceKind = 'engagement_report' | 'assessment_closure_report' | 'project_quality_summary'
export type DocumentIntentState = 'pending' | 'in_flight' | 'done' | 'failed' | 'uncertain' | string

export interface DocumentIntent {
  id: string
  linkId: string
  action: string
  state: DocumentIntentState
  version: number
  attempts: number
  errorCode?: string
  remoteUrl?: string
  remoteId?: string
  createdAt: string
  updatedAt: string
}

export interface DocumentLink {
  id: string
  integrationId: string
  sourceKind: DocumentSourceKind
  sourceRef: string
  scope: 'engagement' | 'project'
  scopeId: string
  container: string
  remoteUrl: string
  remoteVersion: number
  contentHash: string
  revision: number
  retiredAt?: string
  updatedAt: string
}

export interface DocumentRelease {
  skipped: boolean
  intent?: DocumentIntent
  link?: DocumentLink
}

const intent = (value: any): DocumentIntent => ({ id: value?.id ?? '', linkId: value?.link_id ?? '', action: value?.action ?? '', state: value?.state ?? '', version: value?.version ?? 0, attempts: value?.attempts ?? 0, errorCode: value?.error_code || undefined, remoteUrl: value?.remote_url || undefined, remoteId: value?.remote_id || undefined, createdAt: value?.created_at ?? '', updatedAt: value?.updated_at ?? '' })
const link = (value: any): DocumentLink => ({ id: value?.id ?? '', integrationId: value?.integration_id ?? '', sourceKind: value?.source_kind ?? 'engagement_report', sourceRef: value?.source_ref ?? '', scope: value?.scope === 'project' ? 'project' : 'engagement', scopeId: value?.scope_id ?? '', container: value?.container ?? '', remoteUrl: value?.remote_url ?? '', remoteVersion: value?.remote_version ?? 0, contentHash: value?.content_hash ?? '', revision: value?.revision ?? 0, retiredAt: value?.retired_at || undefined, updatedAt: value?.updated_at ?? '' })
const release = (value: any): DocumentRelease => ({ skipped: value?.skipped === true, intent: value?.intent ? intent(value.intent) : undefined, link: value?.link ? link(value.link) : undefined })

export const documentsApi = {
  publish: async (input: { integrationId: string; sourceKind: DocumentSourceKind; scopeId: string; sourceRef: string; requestKey: string }): Promise<DocumentRelease> => release(await req('/document-publications', { method: 'POST', body: JSON.stringify({ integration_id: input.integrationId, source_kind: input.sourceKind, scope_id: input.scopeId, source_ref: input.sourceRef, request_key: input.requestKey }) })),
  documentIntent: async (intentId: string): Promise<DocumentIntent> => intent(await req(`/document-publications/${id(intentId)}`)),
  listEngagementDocuments: async (engagementId: string): Promise<DocumentLink[]> => ((await req(`/engagements/${id(engagementId)}/documents`)) ?? []).map(link),
  listProjectDocuments: async (projectKey: string): Promise<DocumentLink[]> => ((await req(`/projects/${id(projectKey)}/documents`)) ?? []).map(link),
  unpublish: async (linkId: string, requestKey: string): Promise<DocumentRelease> => release(await req(`/document-links/${id(linkId)}`, { method: 'DELETE', body: JSON.stringify({ request_key: requestKey }) })),
}
