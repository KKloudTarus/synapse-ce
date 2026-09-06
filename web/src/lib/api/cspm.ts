import { req } from './client'

// Cloud posture (CSPM) runs (#... cspm). A bounded, read-only live scan of a cloud account's posture.
// Targets carry a provider, a root (account/subscription/project), and a vault credential reference
// (never credential material). The run is durable and executed in an isolated worker; the surface polls
// its status.

export type CloudProvider = 'aws' | 'azure' | 'gcp'

export type CSPMStatus = 'queued' | 'running' | 'succeeded' | 'partial' | 'failed' | 'cancelled'

export interface CloudTarget {
  provider: CloudProvider
  root: string
  credentialRef: string
}

export interface CSPMEvidenceRef {
  scopeKey: string
  id: string
  hash: string
}

export interface CSPMRun {
  id: string
  engagementId: string
  actor: string
  status: CSPMStatus
  complete: boolean
  assets: number
  findings: number
  coverageIssues: unknown[]
  errorCode: string
  evidenceRefs: CSPMEvidenceRef[]
  startedAt: string
  finishedAt: string | null
}

function mapRun(r: any): CSPMRun {
  return {
    id: r?.id ?? '',
    engagementId: r?.engagement_id ?? '',
    actor: r?.actor ?? '',
    status: (r?.status ?? 'queued') as CSPMStatus,
    complete: r?.complete ?? false,
    assets: r?.assets ?? 0,
    findings: r?.findings ?? 0,
    coverageIssues: Array.isArray(r?.coverage_issues) ? r.coverage_issues : [],
    errorCode: r?.error_code ?? '',
    evidenceRefs: Array.isArray(r?.evidence_refs)
      ? r.evidence_refs.map((e: any): CSPMEvidenceRef => ({ scopeKey: e?.scope_key ?? '', id: e?.id ?? '', hash: e?.hash ?? '' }))
      : [],
    startedAt: r?.started_at ?? '',
    finishedAt: r?.finished_at ?? null,
  }
}

export const cspmApi = {
  runCSPM: async (engagementId: string, targets: CloudTarget[]): Promise<CSPMRun> =>
    mapRun(
      await req(`/engagements/${encodeURIComponent(engagementId)}/cspm/runs`, {
        method: 'POST',
        body: JSON.stringify({ targets: targets.map((t) => ({ provider: t.provider, root: t.root, credential_ref: t.credentialRef })) }),
      }),
    ),
  getCSPMRun: async (engagementId: string, runId: string): Promise<CSPMRun> =>
    mapRun(await req(`/engagements/${encodeURIComponent(engagementId)}/cspm/runs/${encodeURIComponent(runId)}`)),
}
