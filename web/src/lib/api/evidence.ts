import type { EvidenceItem, EvidenceLedger } from '../types'
import { blobDownload, req } from './client'

function mapEvidenceItem(r: any): EvidenceItem {
  return {
    id: r.ID ?? '',
    kind: r.Kind ?? '',
    contentBase64: r.Content ?? '',
    hash: r.Hash ?? '',
    previousHash: r.PreviousHash ?? '',
    storageRef: r.StorageRef ?? '',
    createdBy: r.CreatedBy ?? '',
    createdAt: r.CreatedAt ?? null,
  }
}

// ReportType is the deliverable variant. Empty = sca default.
export type ReportType = 'sca' | 'external' | 'internal' | 'retest'

// Options for the report builder. Empty arrays/title mean "everything" /
// the type default – they are only narrowing filters server-side.
export interface ReportBuildOptions {
  type?: ReportType
  sections?: string[]
  statuses?: string[]
  title?: string
}

export const evidenceApi = {
  evidence: async (
    engagementId: string,
  ): Promise<{ intact: boolean; verified: number; head: string; attestation?: { key_id: string; algorithm: string } } | null> => {
    try {
      const r = await req(`/engagements/${encodeURIComponent(engagementId)}/evidence`)
      return {
        intact: r.intact ?? true,
        verified: r.verified ?? 0,
        head: r.head ?? '',
        attestation: r.attestation ? { key_id: r.attestation.key_id, algorithm: r.attestation.algorithm } : undefined,
      }
    } catch {
      return null
    }
  },

  evidenceLedger: async (engagementId: string): Promise<EvidenceLedger> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/evidence`)
    return {
      items: (r.items ?? []).map(mapEvidenceItem),
      intact: r.intact ?? true,
      head: r.head ?? '',
      verified: r.verified ?? 0,
      error: r.error ?? '',
    }
  },

  captureEvidence: async (
    engagementId: string,
    kind: string,
    filename: string,
    note: string,
    contentBase64: string,
  ): Promise<EvidenceItem> =>
    mapEvidenceItem(
      await req(`/engagements/${encodeURIComponent(engagementId)}/evidence`, {
        method: 'POST',
        body: JSON.stringify({ kind, filename, note, content_base64: contentBase64 }),
      }),
    ),

  downloadArtifact: async (engagementId: string, sha: string, filename: string): Promise<void> => {
    const id = encodeURIComponent(engagementId)
    await blobDownload(`/api/v1/engagements/${id}/evidence/${encodeURIComponent(sha)}`, filename || `${sha.slice(0, 12)}.bin`)
  },

  downloadExport: async (engagementId: string, format: 'sarif' | 'openvex' | 'spdx' | 'cyclonedx'): Promise<void> => {
    const id = encodeURIComponent(engagementId)
    await blobDownload(`/api/v1/engagements/${id}/export/${format}`, `synapse-${engagementId}.${format}.json`)
  },

  downloadReport: async (engagementId: string): Promise<void> => {
    const id = encodeURIComponent(engagementId)
    await blobDownload(`/api/v1/engagements/${id}/report.pdf`, `synapse-${engagementId}-report.pdf`)
  },

  downloadBundle: async (engagementId: string): Promise<void> => {
    const id = encodeURIComponent(engagementId)
    await blobDownload(`/api/v1/engagements/${id}/bundle`, `synapse-${engagementId}-bundle.json`)
  },

  downloadReportDoc: async (
    engagementId: string,
    format: 'html' | 'docx',
    opts: ReportBuildOptions = {},
  ): Promise<void> => {
    const id = encodeURIComponent(engagementId)
    const q = new URLSearchParams()
    if (opts.type && opts.type !== 'sca') q.set('type', opts.type)
    for (const s of opts.sections ?? []) q.append('section', s)
    for (const s of opts.statuses ?? []) q.append('status', s)
    if (opts.title?.trim()) q.set('title', opts.title.trim())
    const qs = q.toString()
    await blobDownload(
      `/api/v1/engagements/${id}/report.${format}${qs ? `?${qs}` : ''}`,
      `synapse-${engagementId}-report.${format}`,
    )
  },
}
