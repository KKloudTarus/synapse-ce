import type { LegalHold, PrivacyExportBundle } from '../types'
import { req } from './client'

// Privacy & data governance (#635). legalhold.Hold and the export bundle's holds are untagged
// PascalCase; the export bundle's own fields are snake_case (a view struct). Mapped in one place.

function mapLegalHold(raw: any): LegalHold {
  return {
    tenantId: raw?.TenantID ?? '',
    engagementId: raw?.EngagementID ?? '',
    reason: raw?.Reason ?? '',
    placedBy: raw?.PlacedBy ?? '',
    placedAt: raw?.PlacedAt ?? '',
    releasedBy: raw?.ReleasedBy ?? '',
    releasedAt: raw?.ReleasedAt ?? '',
  }
}

export const governanceApi = {
  // Fleet-wide list of ACTIVE legal holds.
  listLegalHolds: async (): Promise<LegalHold[]> => {
    const res = await req('/fleet/legal-holds')
    return Array.isArray(res?.holds) ? res.holds.map(mapLegalHold) : []
  },

  // Place a hold on one engagement's data (PermReview). Idempotent server-side.
  placeLegalHold: async (engagementId: string, reason: string): Promise<LegalHold> =>
    mapLegalHold(
      await req(`/fleet/engagements/${encodeURIComponent(engagementId)}/legal-hold`, {
        method: 'PUT',
        body: JSON.stringify({ reason }),
      }),
    ),

  // Release the active hold on an engagement (PermReview). Returns 204.
  releaseLegalHold: async (engagementId: string): Promise<void> => {
    await req(`/fleet/engagements/${encodeURIComponent(engagementId)}/legal-hold`, { method: 'DELETE' })
  },

  // Subject-access / DPO export for one engagement (read-only, audited).
  privacyExport: async (engagementId: string): Promise<PrivacyExportBundle> => {
    const res = await req(`/fleet/engagements/${encodeURIComponent(engagementId)}/privacy-export`)
    return {
      engagementId: res?.engagement_id ?? engagementId,
      generatedAt: res?.generated_at ?? '',
      detectionCount: res?.detection_count ?? 0,
      legalHolds: Array.isArray(res?.legal_holds) ? res.legal_holds.map(mapLegalHold) : [],
    }
  },

  // On-demand deletion / right-to-erasure of an engagement's detection projection (PermReview,
  // legal-hold-checked, audited). DESTRUCTIVE — the caller must confirm and supply a reason.
  purgeEngagementDetectionData: async (engagementId: string, reason: string): Promise<{ purged: number }> => {
    const res = await req(`/fleet/engagements/${encodeURIComponent(engagementId)}/detection-data`, {
      method: 'DELETE',
      body: JSON.stringify({ reason }),
    })
    return { purged: res?.purged ?? 0 }
  },
}
