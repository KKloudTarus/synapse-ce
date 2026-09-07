import { req } from './client'

// AI-proposed finding write-up drafts (#... writeupdraft). An agent proposes description/remediation
// prose for a finding; a human with review authority edits, then accepts or rejects it. Separation of
// duties is enforced server-side: the acceptor must not be the proposer. Nothing here renders into a
// report on its own — an accepted draft becomes eligible to be applied to its finding.
//
// The domain Draft carries no JSON tags, so the wire keys are Go PascalCase; this maps them and tolerates
// a snake_case shape in case tags are added later.

export type WriteupDraftState = 'proposed' | 'accepted' | 'rejected'

export interface WriteupDraft {
  id: string
  engagementId: string
  findingId: string
  description: string
  remediation: string
  state: WriteupDraftState
  proposedBy: string
  decidedBy: string
  createdAt: string
  updatedAt: string
}

function mapDraft(r: any): WriteupDraft {
  return {
    id: r?.ID ?? r?.id ?? '',
    engagementId: r?.EngagementID ?? r?.engagement_id ?? '',
    findingId: r?.FindingID ?? r?.finding_id ?? '',
    description: r?.Description ?? r?.description ?? '',
    remediation: r?.Remediation ?? r?.remediation ?? '',
    state: (r?.State ?? r?.state ?? 'proposed') as WriteupDraftState,
    proposedBy: r?.ProposedBy ?? r?.proposed_by ?? '',
    decidedBy: r?.DecidedBy ?? r?.decided_by ?? '',
    createdAt: r?.CreatedAt ?? r?.created_at ?? '',
    updatedAt: r?.UpdatedAt ?? r?.updated_at ?? '',
  }
}

export const writeupApi = {
  listWriteupDrafts: async (engagementId: string): Promise<WriteupDraft[]> => {
    const r = await req(`/engagements/${encodeURIComponent(engagementId)}/writeup-drafts`)
    return Array.isArray(r?.writeup_drafts) ? r.writeup_drafts.map(mapDraft) : []
  },
  editWriteupDraft: async (
    engagementId: string,
    draftId: string,
    body: { description: string; remediation: string },
  ): Promise<WriteupDraft> =>
    mapDraft(
      await req(`/engagements/${encodeURIComponent(engagementId)}/writeup-drafts/${encodeURIComponent(draftId)}/edit`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    ),
  acceptWriteupDraft: async (engagementId: string, draftId: string): Promise<WriteupDraft> =>
    mapDraft(
      await req(`/engagements/${encodeURIComponent(engagementId)}/writeup-drafts/${encodeURIComponent(draftId)}/accept`, {
        method: 'POST',
      }),
    ),
  rejectWriteupDraft: async (engagementId: string, draftId: string): Promise<WriteupDraft> =>
    mapDraft(
      await req(`/engagements/${encodeURIComponent(engagementId)}/writeup-drafts/${encodeURIComponent(draftId)}/reject`, {
        method: 'POST',
      }),
    ),
}
