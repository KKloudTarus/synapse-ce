import { ApiError, req } from './client'

export type SIEMProvider = 'splunk_hec' | 'elasticsearch' | 'syslog_tls' | 'microsoft_sentinel'
export type SIEMDataClass = 'signal' | 'summary' | 'detail'
export type SIEMAckMode = 'hec_acceptance' | 'indexer_ack' | 'bulk_item' | 'transport_write' | 'ingestion_acceptance'
export type SIEMReplay = 'cursor' | 'head'

export interface SIEMSink {
  id: string
  tenant_id: string
  name: string
  provider: SIEMProvider
  origin: string
  target: string
  data_class: SIEMDataClass
  ack_mode: SIEMAckMode
  indexer_ack_supported: boolean
  paused: boolean
  enabled: boolean
  generation: number
  secret_version: number
  version: number
  channel: string
  blocked_reason?: string
  created_at: string
  updated_at: string
}

export interface SIEMSinkInput {
  name: string
  provider: SIEMProvider
  origin: string
  target?: string
  data_class?: SIEMDataClass
  ack_mode?: SIEMAckMode
  indexer_ack_supported?: boolean
  allow_hosts?: string[]
  secret?: string
  version?: number
}

export interface SIEMPartition {
  source: string
  caught_up: boolean
  lag_records: number
  backlog_age_seconds: number
  cursor: string
  blocked?: string
  guarantee: string
  legacy_v1: boolean
  coverage_note: string
}

export interface SIEMStatus {
  sink: SIEMSink
  partitions: SIEMPartition[]
}

async function optional<T>(path: string): Promise<T | null> {
  try {
    return await req(path)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null
    throw error
  }
}

export const siemApi = {
  listSIEMSinks: async (): Promise<SIEMSink[] | null> =>
    (await optional<{ items: SIEMSink[] }>('/siem/sinks'))?.items ?? null,
  createSIEMSink: (input: SIEMSinkInput): Promise<SIEMSink> =>
    req('/siem/sinks', { method: 'POST', body: JSON.stringify(input) }),
  updateSIEMSink: (id: string, input: SIEMSinkInput): Promise<SIEMSink> =>
    req(`/siem/sinks/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(input) }),
  rotateSIEMSecret: (id: string, secret: string, version: number): Promise<SIEMSink> =>
    req(`/siem/sinks/${encodeURIComponent(id)}/secret`, {
      method: 'POST',
      body: JSON.stringify({ secret, version }),
    }),
  changeSIEMOrigin: (
    id: string,
    origin: string,
    secret: string,
    replay: SIEMReplay,
    version: number,
  ): Promise<SIEMSink> =>
    req(`/siem/sinks/${encodeURIComponent(id)}/origin`, {
      method: 'POST',
      body: JSON.stringify({ origin, secret, replay, version }),
    }),
  pauseSIEMSink: (id: string, version: number): Promise<SIEMSink> =>
    req(`/siem/sinks/${encodeURIComponent(id)}/pause`, {
      method: 'POST',
      body: JSON.stringify({ version }),
    }),
  resumeSIEMSink: (id: string, version: number): Promise<SIEMSink> =>
    req(`/siem/sinks/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ version }),
    }),
  testSIEMSink: (id: string): Promise<{ guarantee: string; result: string }> =>
    req(`/siem/sinks/${encodeURIComponent(id)}/test`, { method: 'POST' }),
  siemSinkStatus: (id: string): Promise<SIEMStatus> =>
    req(`/siem/sinks/${encodeURIComponent(id)}/status`),
}
